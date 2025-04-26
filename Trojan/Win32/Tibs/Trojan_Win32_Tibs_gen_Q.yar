
rule Trojan_Win32_Tibs_gen_Q{
	meta:
		description = "Trojan:Win32/Tibs.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c3 58 59 5a c1 e3 09 c1 e3 07 8d 7c 1f fc 81 ef 00 80 00 00 81 c7 00 80 ff ff e2 c5 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}