
rule Trojan_Win32_Copak_SPDX_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 1a 40 89 c7 01 c6 81 e3 ff 00 00 00 f7 d6 01 f7 81 ee 62 79 63 11 31 19 81 ef b9 36 73 9d 29 f8 81 e8 1f b4 e4 ce 41 09 f8 09 fe 42 89 c6 89 c7 81 f9 } //00 00 
	condition:
		any of ($a_*)
 
}