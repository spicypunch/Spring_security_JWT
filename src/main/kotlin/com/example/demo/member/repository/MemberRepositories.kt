package com.example.demo.member.repository

import com.example.demo.member.entity.Member
import org.springframework.data.jpa.repository.JpaRepository

interface MemberRepository : JpaRepository<Member, Long> {
    // ID 중복검사
    fun findByLoginId(loginId: String): Member?
}