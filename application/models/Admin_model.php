<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Admin_model extends CI_Model {

    public function get_all_admin() {
        $query = $this->db->get('admin');
        return $query->result();
    }

    public function get_admin_by_id($id) {
        return $this->db->get_where('admin', ['id' => $id])->row();
    }

    public function create_admin($data) {
        $this->db->insert('admin', $data);
        return $this->db->insert_id();
    }

    public function update_admin($id, $data) {
        $this->db->where('id', $id);
        return $this->db->update('admin', $data);
    }

    public function delete_admin($id) {
        return $this->db->delete('admin', ['id' => $id]);
    }
}
