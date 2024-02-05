
rule Trojan_Win32_Farfli_RPT_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 0c 06 8b 44 24 1c 0f be 04 07 99 f7 fb 8b c6 80 c2 4f 30 11 59 99 f7 f9 47 85 d2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_RPT_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 8c 55 f4 fd ff ff 83 f9 3b 74 08 83 f9 64 74 03 83 f1 1b 66 89 8c 55 ec fb ff ff 42 3b d0 7c de } //00 00 
	condition:
		any of ($a_*)
 
}