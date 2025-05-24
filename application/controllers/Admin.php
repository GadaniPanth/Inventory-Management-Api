<?php
// phpinfo();
// exit;
defined('BASEPATH') OR exit('No direct script access allowed');
#[\AllowDynamicProperties]
class Admin extends CI_Controller {
    public $auth_token = "secret_123";

    public function __construct() {
        parent::__construct();
        $method = $this->uri->segment(2);
        if ($method !== 'login') {
            $this->check_token();
        }
        $this->load->database();
        $this->load->model('Admin_model');
        $this->load->model('Products_model');
        header('Content-Type: application/json');
        $this->load->library('upload');
        // $this->load->library('session');
        // $this->load->library('password');
    }

    //Login private Method
    private function _is_loggedIn($verified, $admin){
        if($verified){
            // echo json_encode(['status'=> 1, 'message'=> 'Admin Logged In!']);
            //  $newdata = array(
            //     'id'  => $admin_data->id,
            //     'email'     => $admin_data->email,
            //     'logged_in' => 1
            // );
            // $this->session->set_admindata('loggedInAdmin',$newdata);
            // echo "<br>";
            // echo $this->session->has_admindata('loggedInAdmin');
            // echo "<br>";

            $admin_data = [
                'name'  => $admin->name,
                'email' => $admin->email,
                'password' => $admin->password,
            ];
            echo json_encode (["status"=> 1, "message"=> "Admin authenticated successfully.", "auth_token"=> $this-> auth_token, 'admin_details'=> $admin_data]);
            return;
        };
        
        echo json_encode(['status'=> 0, 'message'=> 'Invalid Credentials.']);
        return;
    }
    
    // Token
    private function check_token() {
        $headers = $this->input->request_headers();

        if (!isset($headers['Authorization'])) {
            // show_error('Authorization header missing', 401);
            echo json_encode(["status"=> 401, "message"=> "Authorization header missing!"]);
            exit;
        }

        $auth_header = $headers['Authorization'];
        if (strpos($auth_header, 'Bearer ') !== 0) {
            // show_error('Invalid token format', 401);
            echo json_encode(["status"=> 401, "message"=> "Invalid token format"]);
            exit;
        }

        $token = substr($auth_header, 7);
        
        if ($token !== $this-> auth_token) {
            // show_error('Invalid token', 401);
            echo json_encode(["status"=> 401, "message"=>'Invalid token']);
            exit;
        }
    }

    public function data_get() {
        echo json_encode(['message' => 'Authorized access']);
    }

// Admin Build

    //Get Admin
    public function index() {
        if ($this->input->method() !== 'get') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use GET method.']);
            return;
        }
        // if(empty($this->session->loggedInAdmin)){
        //     echo json_encode(['status' => 0, 'message' => 'Not Logged In!']);
        //     return;
        // }
        $this->load->helper('url');
        $query = $this->db->get('admin');
        $result = $query->result();

        if(!empty($result)){
            echo json_encode(["status"=>1,"admins"=>$result]);
        }else {
            echo json_encode(["status"=> 0, "message"=> "No Admin Found!"]);
        }
        return;
    }

    //Create Admin
    public function create() {
        if ($this->input->method() !== 'post') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use POST method.']);
            return;
        }
        // if(empty($this->session->loggedInAdmin)){
        //     echo json_encode(['status' => 0, 'message' => 'Not Logged In!']);
        //     return;
        // }
        // $query = $this->db->get('admin');


        $name  = $this->input->post('name');
        $email = $this->input->post('email');
        $password = $this->input->post('password');
        if(empty($name) || empty($email) || empty($password)){
            echo json_encode(['status' => 0, 'message' => 'Required name, email and password.']);
            return;
        }
        $password = password_hash($password, PASSWORD_BCRYPT);
        $admin_data = [
            'name'  => $name,
            'email' => $email,
            'password' => $password,
        ];

        // echo json_encode(['status' => 0, 'message' => $admin_data]);
        // exit;

        $insert_id = $this->Admin_model->create_admin($admin_data);

        if ($insert_id) {
            echo json_encode(['status' => 1, 'message' => 'Admin created', 'admin_id' => $insert_id]);
        } else {
            $db_error = $this->db->error();
            echo json_encode(['status' => 0,'message' => $db_error['message']]);
        }
        return;
    }

    //Get Admin By ID
    public function get_admin($id = null){
        if ($this->input->method() !== 'get') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use GET method.']);
            return;
        }
        if ($id == null) {
            echo json_encode(['status' => 0, 'message' => 'Required Id as Params.']);
            return;
        }
        // if(empty($this->session->loggedInAdmin)){
        //     echo json_encode(['status' => 0, 'message' => 'Not Logged In!']);
        //     return;
        // }
        $admin = $this->Admin_model->get_admin_by_id($id);
        if (!empty($admin)) {
            echo json_encode(['status' => 1, 'admin' => $admin]);
        } else {
            echo json_encode(['status' => 0, 'message' => 'Admin Not Found with id ' . $id]);
        }
        return;
    }

    //Update Admin
    public function update($id = null) {
        if ($this->input->method() !== 'post') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use POST method.']);
            return;
        }
        if ($id == null) {
            echo json_encode(['status' => 0, 'message' => 'Required Id as Params.']);
            return;
        }
        // if(empty($this->session->loggedInAdmin)){
        //     echo json_encode(['status' => 0, 'message' => 'Not Logged In!']);
        //     return;
        // }

        $admin = $this->Admin_model->get_admin_by_id($id);
        
        if (empty($admin)) {
            echo json_encode(['status' => 0, 'message' => 'Admin not found']);
            return;
        }

        $name  = !empty($this->input->post('name')) ? $this->input->post('name') : $admin->name;
        $email =  !empty($this->input->post('email')) ? $this->input->post('email') : $admin->email;
        $password =  !empty($this->input->post('password')) ? $this->input->post('password') : $admin->password;

        if ($name == $admin->name && $email == $admin->email && $password == $admin->password) {
            echo json_encode(['status' => 0, 'message' => 'Data is not Changed!']);
            return;
        }
        
        $password = password_hash($password, PASSWORD_BCRYPT);
        $update_data = [
            'name'  => $name,
            'email' => $email,
            'password' => $password,
        ];

        // echo json_encode($update_data);
        // exit;

        $updated = $this->Admin_model->update_admin($id, $update_data);
        // echo $updated;
        // exit;

        if ($updated) {
            echo json_encode(['status' => 1, 'message' => 'Admin updated successfully']);
        } else {
            $db_error = $this->db->error();
            echo json_encode(['status' => 0,'message' => $db_error['message']]);        
        }
        return;
    }

    //Delete Admin
    public function delete($id = null) {
        if ($this->input->method() !== 'delete') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use DELETE method.']);
            return;
        }
        if ($id == null) {
            echo json_encode(['status' => 0, 'message' => 'Required Id as Params.']);
            return;
        }
        // if(empty($this->session->loggedInAdmin)){
        //     echo json_encode(['status' => 0, 'message' => 'Not Logged In!']);
        //     return;
        // }
        $admin = $this->Admin_model->get_admin_by_id($id);
        if (!$admin) {
            echo json_encode(['status' => 0, 'message' => 'Admin not found!']);
            return;
        }
        $result = $this->Admin_model->delete_admin($id);
        echo json_encode([
            'status' => $result,
            'message' => $result ? 'Deleted admin of id ' . $id : 'Failed to delete admin.'
        ]);
        return;
    }

    //Authentication

    //Login
    public function login() {
        if ($this->input->method() !== 'post') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use POST method.']);
            return;
        }
        // if(!empty($this->session->loggedInAdmin)){
        //     echo json_encode(['status' => 1, 'message' => 'Already Logged In!']);
        //     return;
        // }
        $email = $this->input->post('email');
        $password = $this->input->post('password');

        if(empty($email) || empty($password)){
            echo json_encode(['status'=> 0, 'message'=> "Email & Password can't be Empty!"]);
            return;
        }
        $admin = $this->db->get_where('admin', ['email'=> $email])->row();
        if(empty($admin)){
            echo json_encode(["status"=> 0, "message"=> "Email Not Exists!"]);
            return;
        }

        $pass_verified = 0;

        if(password_verify($password, $admin->password)){
            $pass_verified = 1;
        }
        
        $this->_is_loggedIn($pass_verified, $admin);
    }

    // public function logout() {
        // if(empty($this->session->loggedInAdmin)){
        //     echo json_encode(['status' => 0, 'message' => 'Not Logged In!']);
        //     return;
        // }
        // $this->session->unset_admindata('loggedInAdmin');
        // if(empty($this->session->loggedInAdmin)){
        //     echo json_encode(['status' => 1, 'message' => 'Logged Out!']);
        //     return;
        // }
    // }


//Products Build

    //Get Products
    public function products($id = null) {
        if ($this->input->method() !== 'get') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use GET method.']);
            return;
        }
        $this->load->helper('url');
        $base_url = base_url();

        if($id){
            $result =  $this->Products_model->get_product_by_id($id);
            if(!empty($result)){
                    $updated_images=[];
                    $decoded_images = json_decode($result->image);
                    foreach($decoded_images as $image){
                        $updated_images[] = $base_url . 'uploads/' . $image;
                    }
                    $result->image = $updated_images;
                    echo json_encode(["status"=>1,"products"=>$result]);
                    return;
                }else {
                    echo json_encode(["status"=> 0, "message"=> "No Product Found with id " . $id]);
                    return;
            }
        }
        // if(empty($this->session->loggedInAdmin)){
        //     echo json_encode(['status' => 0, 'message' => 'Not Logged In!']);
        //     return;
        // }
       
        $query = $this->db->get('products');
        $result = $query->result();

        if(!empty($result)){
            foreach($result as $product){
                $updated_images=[];
                $decoded_images = json_decode($product->image);
                foreach($decoded_images as $image){
                    $updated_images[] = $base_url . 'uploads/' . $image;
                }
                // echo $user->image;
                $product->image = $updated_images;
            }
            echo json_encode(["status"=>1,"products"=>$result]);
        }else {
            echo json_encode(["status"=> 0, "message"=> "No Product Found!"]);
        }
        return;
    }

    //Add Product
    public function add_product() {
        if ($this->input->method() !== 'post') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use POST method.']);
            return;
        }

        $name  = $this->input->post('name');
        $category = $this->input->post('category');
        $description = $this->input->post('description');
        $amount = $this->input->post('amount');
        $stock = $this->input->post('stock');
        if(empty($name) || empty($category) || empty($description) || empty($amount) || empty($stock)){
            echo json_encode(['status' => 0, 'message' => 'Required name, category, description, amount and stock.']);
            return;
        }
        $this->load->helper('url');
        $config['upload_path'] = FCPATH . 'uploads/';
        $config['allowed_types'] = 'jpg|jpeg|png|gif';
        // $config['max_size']      = 2048;
        $config['encrypt_name']  = TRUE;

        $this->upload->initialize($config);

        $image_names = [];

        if (!empty($_FILES['image']['name'][0])) {
            $count = count($_FILES['image']['name']);

            for ($i = 0; $i < $count; $i++) {
                $_FILES['single_image']['name']     = $_FILES['image']['name'][$i];
                $_FILES['single_image']['type']     = $_FILES['image']['type'][$i];
                $_FILES['single_image']['tmp_name'] = $_FILES['image']['tmp_name'][$i];
                $_FILES['single_image']['error']    = $_FILES['image']['error'][$i];
                $_FILES['single_image']['size']     = $_FILES['image']['size'][$i];

                if (!$this->upload->do_upload('single_image')) {
                    echo json_encode(['status' => false, 'message' => $this->upload->display_errors()]);
                    return;
                } else {
                    $uploaded_data = $this->upload->data();
                    $image_names[] = $uploaded_data['file_name'];
                }
            }
        } else {
            $image_names[] = 'No-Image-Placeholder.svg';
        }


        $product_data = [
            'name'  => $name,
            'category' => $category,
            'image' =>  json_encode($image_names),
            'description' => $description,
            'amount' => $amount,
            'stock' => $stock,
        ];

        // echo json_encode(['status' => 0, 'message' => $admin_data]);
        // exit;

        $insert_id = $this->Products_model->add_product($product_data);

        if ($insert_id) {
            echo json_encode(['status' => 1, 'message' => 'Product created', 'product_id' => $insert_id]);
        } else {
            $db_error = $this->db->error();
            echo json_encode(['status' => 0,'message' => $db_error['message']]);
        }
        return;

    }

    //Update Product
    public function update_product($id = null) {
        if ($this->input->method() !== 'post') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use POST method.']);
            return;
        }
        if ($id == null) {
            echo json_encode(['status' => 0, 'message' => 'Required Id as Params.']);
            return;
        }

        $product = $this->Products_model->get_product_by_id($id);
        
        if (empty($product)) {
            echo json_encode(['status' => false, 'message' => 'Product not found']);
            return;
        }

        $name  = $this->input->post('name') ? $this->input->post('name') : $product->name;
        $category = $this->input->post('category') ? $this->input->post('category') : $product->category;
        $description = $this->input->post('description') ? $this->input->post('description') : $product->description;
        $amount = $this->input->post('amount') ? $this->input->post('amount') : $product->amount;
        $stock = $this->input->post('stock') ? $this->input->post('stock') : $product->stock;
        
        // if(empty($name) || empty($category) || empty($description) || empty($amount) || empty($stock)){
        //     echo json_encode(['status' => 0, 'message' => 'Required name, category, description, amount and stock.']);
        //     return;
        // }

        $this->load->helper('url');
        $config['upload_path'] = FCPATH . 'uploads/';
        $config['allowed_types'] = 'jpg|jpeg|png|gif';
        // $config['max_size']      = 2048;
        $config['encrypt_name']  = TRUE;

        $this->upload->initialize($config);

        $image_names = [];
        $image_changed = false;

        if (!empty($_FILES['image']['name'][0])) {
            $count = count($_FILES['image']['name']);
            $image_changed = true;
            for ($i = 0; $i < $count; $i++) {
                $_FILES['single_image']['name']     = $_FILES['image']['name'][$i];
                $_FILES['single_image']['type']     = $_FILES['image']['type'][$i];
                $_FILES['single_image']['tmp_name'] = $_FILES['image']['tmp_name'][$i];
                $_FILES['single_image']['error']    = $_FILES['image']['error'][$i];
                $_FILES['single_image']['size']     = $_FILES['image']['size'][$i];

                if (!$this->upload->do_upload('single_image')) {
                    echo json_encode(['status' => false, 'message' => $this->upload->display_errors()]);
                    return;
                } else {
                    $uploaded_data = $this->upload->data();
                    $image_names[] = $uploaded_data['file_name'];
                }
            }
        } else {
            $image_changed = false;
            foreach(json_decode($product->image) as $image){
                $image_names[] = $image;
            }
        }

        // echo json_encode($image_names);
        // exit;

        if (($name == $product->name && $category == $product->category && $description == $product->description && $amount == $product->amount && $stock == $product->stock) && !$image_changed) {
            echo json_encode(['status' => 0, 'message' => 'Data is not Changed!']); //Not Works for Images
            return;
        }

        $product_data = [
            'name'  => $name,
            'category' => $category,
            'image' =>  json_encode($image_names),
            'description' => $description,
            'amount' => $amount,
            'stock' => $stock,
        ];

        // echo json_encode(['status' => 0, 'message' => $admin_data]);
        // exit;

        $updated = $this->Products_model->update_product($id, $product_data);

        if ($updated) {
            echo json_encode(['status' => 1, 'message' => 'Product Updated']);
        } else {
            $db_error = $this->db->error();
            echo json_encode(['status' => 0,'message' => $db_error['message']]);
        }
        return;

    }

    //Get Product Stock
    public function get_product_stock($id = null) {
        if ($this->input->method() !== 'get') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use GET method.']);
            return;
        }
        if ($id == null) {
            echo json_encode(['status' => 0, 'message' => 'Required Id as Params.']);
            return;
        }

        $result = $this->Products_model->get_product_stock($id);
        if(empty($result)){
            echo json_encode(['status' => 0, "message"=> "Product Not Found!"]);
            return;
        }
        echo json_encode(['status' => 1, "product_name"=>$result->name, "product_stock"=>$result->stock]);
        return;
    }

    //Get Product By Name
    public function get_product_by_name($name = null) {
        if ($this->input->method() !== 'get') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use GET method.']);
            return;
        }
        if ($name == null) {
            echo json_encode(['status' => 0, 'message' => 'Required Name as Params.']);
            return;
        }
        $this->load->helper('url');
        $base_url = base_url();
        $name = urldecode($name);

        // echo json_encode([$name]);
        // exit;
        $result =  $this->db->get_where('products', ['name' => $name])->row();
        if(empty($result)){
            echo json_encode(['status' => 0, "message"=> "Product Not Found!"]);
            return;
        }
        $updated_images=[];
        $decoded_images = json_decode($result->image);
        foreach($decoded_images as $image){
            $updated_images[] = $base_url . 'uploads/' . $image;
        }
        $result->image = $updated_images;
        echo json_encode(['status' => 1, "product"=>$result]);
        return;
    }

    //Delete Product
    public function delete_product($id = null) {
        if ($this->input->method() !== 'delete') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use DELETE method.']);
            return;
        }
        if ($id == null) {
            echo json_encode(['status' => 0, 'message' => 'Required Id as Params.']);
            return;
        }

        $product = $this->Products_model->get_product_by_id($id);
        if (!$product) {
            echo json_encode(['status' => 0, 'message' => 'Product not found!']);
            return;
        }
        $result = $this->Products_model->delete_product($id);
        echo json_encode([
            'status' => $result,
            'message' => $result ? 'Deleted Product of id ' . $id : 'Failed to delete product.'
        ]);
        return;
    }

    //Page Not Found 404
    public function not_found404() {
        echo json_encode(["status"=> '404', "message"=> "Page Not Found!"]);
        // $this->output->set_status_header(404)->set_content_type('application/json')->set_output(json_encode(["status" => 404,"message" => "Page Not Found!"]));
    }
}