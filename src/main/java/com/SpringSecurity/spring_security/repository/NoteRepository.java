package com.SpringSecurity.spring_security.repository;

import com.SpringSecurity.spring_security.model.Note;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface NoteRepository extends JpaRepository<Note, Long> {
    @Transactional// Ensure transactions for handling LOBs
    List<Note> findByOwnerUsername(String ownerUsername);
}
