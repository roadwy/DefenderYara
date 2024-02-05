
rule Trojan_Win32_REntS_SIBT8_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT8!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 02 05 90 01 04 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //01 00 
		$a_03_1 = {88 0a 8b 55 90 01 01 03 55 90 01 01 8a 02 2c 01 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //01 00 
		$a_03_2 = {8a 1a 84 db 74 90 01 01 8b c8 8d 52 90 01 01 c1 e0 90 01 01 03 c1 0f be cb 8a 1a 03 c1 84 db 75 90 01 01 8b 4d 08 3b 45 0c 74 90 01 01 8b 55 90 01 01 46 3b f1 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}