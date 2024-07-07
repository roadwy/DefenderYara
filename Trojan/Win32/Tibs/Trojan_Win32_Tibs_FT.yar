
rule Trojan_Win32_Tibs_FT{
	meta:
		description = "Trojan:Win32/Tibs.FT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {87 d1 58 68 90 01 04 ff 15 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 90 02 05 81 90 03 01 01 44 6c 24 90 01 01 00 00 90 01 02 f7 64 24 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}