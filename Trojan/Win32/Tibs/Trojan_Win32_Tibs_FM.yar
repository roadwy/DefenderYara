
rule Trojan_Win32_Tibs_FM{
	meta:
		description = "Trojan:Win32/Tibs.FM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {87 d1 81 c4 90 01 04 81 ec 90 01 04 90 03 04 04 68 90 01 04 6a 90 01 01 ff 15 90 01 04 90 03 02 02 c1 e0 69 c0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}