
rule Trojan_Win32_Tibs_LD{
	meta:
		description = "Trojan:Win32/Tibs.LD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 5a 01 df 90 03 05 05 83 ef 90 01 01 81 ef 90 01 04 81 ef 90 01 04 e2 90 14 90 03 01 0d ab 90 03 01 04 57 6a 90 01 01 e8 90 01 04 52 51 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}