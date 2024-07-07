
rule Trojan_Win32_Tibs_gen_P{
	meta:
		description = "Trojan:Win32/Tibs.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c3 58 59 5a c1 e3 10 8d 7c 1f fc 81 ef 00 00 01 00 e2 d1 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}