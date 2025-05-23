<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Products_model extends CI_Model {

    public function get_all_products() {
        $query = $this->db->get('products');
        return $query->result();
    }

    public function get_product_by_id($id) {
        return $this->db->get_where('products', ['id' => $id])->row();
    }

    public function get_products_by_category($category) {
        return $this->db->get_where('products', ['category' => $category])->row();
    }

    public function get_product_stock($id) {
        return $this->db->get_where('products', ['id' => $id])->row();
    }

    public function add_product($data) {
        $this->db->insert('products', $data);
        return $this->db->insert_id();
    }

    public function update_product($id, $data) {
        $this->db->where('id', $id);
        return $this->db->update('products', $data);
    }

    public function delete_product($id) {
        return $this->db->delete('products', ['id' => $id]);
    }
}
