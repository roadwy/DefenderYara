
rule Trojan_Win32_Tibs_JAC{
	meta:
		description = "Trojan:Win32/Tibs.JAC,SIGNATURE_TYPE_PEHSTR_EXT,57 04 57 04 01 00 00 "
		
	strings :
		$a_03_0 = {59 5a c1 e3 90 01 01 c1 e3 90 01 01 8d 7c 1f 90 01 01 81 ef 90 01 04 81 c7 90 01 04 e2 c8 c3 90 00 } //1111
	condition:
		((#a_03_0  & 1)*1111) >=1111
 
}