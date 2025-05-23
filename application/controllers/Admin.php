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
        $this->load->helper('url');
        header('Content-Type: application/json');
        // $this->load->library('session');
        // $this->load->library('password');
    }

    private function _is_loggedIn($verified, $admin){
        $base_url = base_url();

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

    public function index() {
        $base_url = base_url();
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
            echo json_encode(["status"=> 0, "messgae"=> "No Admin Found!"]);
        }
        return;
    }

    public function create() {
        if ($this->input->method() !== 'post') {
            echo json_encode(['status' => 0, 'message' => 'Invalid HTTP method. Use POST method.']);
            return;
        }
        // if(empty($this->session->loggedInAdmin)){
        //     echo json_encode(['status' => 0, 'message' => 'Not Logged In!']);
        //     return;
        // }
        $this->load->library('upload');
        $base_url = base_url();
        $query = $this->db->get('admin');


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
        $base_url = base_url();
        $admin = $this->Admin_model->get_admin_by_id($id);
        if (!empty($admin)) {
            echo json_encode(['status' => 1, 'admin' => $admin]);
        } else {
            echo json_encode(['status' => 0, 'message' => 'Admin Not Found with id ' . $id]);
        }
        return;
    }

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
        $this->load->helper('url');
        $this->load->library('upload');
        $base_url = base_url();

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
            echo json_encode(['status' => 0, 'message' => 'Admin not found']);
            return;
        }
        $result = $this->Admin_model->delete_admin($id);
        echo json_encode([
            'status' => $result,
            'message' => $result ? 'Deleted admin of id ' . $id : 'Failed to delete admin'
        ]);
        return;
    }

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

    public function not_found404() {
        echo json_encode(["status"=> '404', "message"=> "Page Not Found!"]);
        // $this->output->set_status_header(404)->set_content_type('application/json')->set_output(json_encode(["status" => 404,"message" => "Page Not Found!"]));
    }
}