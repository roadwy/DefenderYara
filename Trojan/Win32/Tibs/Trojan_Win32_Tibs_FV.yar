
rule Trojan_Win32_Tibs_FV{
	meta:
		description = "Trojan:Win32/Tibs.FV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {87 02 03 55 08 03 55 0c 90 03 03 04 90 01 10 90 09 20 00 90 02 40 69 c0 90 01 04 b9 90 01 04 81 e9 90 01 04 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}