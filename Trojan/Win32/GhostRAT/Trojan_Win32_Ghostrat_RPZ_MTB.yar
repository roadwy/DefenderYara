
rule Trojan_Win32_Ghostrat_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Ghostrat.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {47 83 c6 04 83 c3 02 3b 7d f4 72 b8 eb 1d 0f b7 0b 3b 4d f0 77 15 8b 45 ec 8b 40 1c 8d 04 88 8b 4d fc 8b 04 08 03 c1 74 02 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}