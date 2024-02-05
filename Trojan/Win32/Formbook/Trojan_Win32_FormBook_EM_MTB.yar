
rule Trojan_Win32_FormBook_EM_MTB{
	meta:
		description = "Trojan:Win32/FormBook.EM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {b9 81 a8 00 00 25 ce 86 00 00 40 59 3d 3a b3 00 00 74 06 49 b9 66 8b 00 00 41 81 ea b2 b1 00 00 81 e9 08 82 01 00 f7 d2 bb 7c 77 00 00 81 e2 45 85 00 00 81 e1 a1 f6 00 00 b8 a0 86 01 00 43 81 e9 ed 64 01 00 40 5b f7 d0 59 48 81 f1 bc 13 01 00 ba 7c bf 00 00 81 e3 75 66 01 00 c2 dd 19 } //00 00 
	condition:
		any of ($a_*)
 
}