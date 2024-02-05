
rule Trojan_Win32_Emotet_KDS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.KDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {8a 44 1c 10 88 44 2c 10 02 c1 25 ff 00 00 00 88 4c 1c 10 8a 0c 32 8a 44 04 10 32 c8 88 0c 32 42 3b d7 7c } //02 00 
		$a_02_1 = {8b 45 18 8b 4d 10 03 08 8b 55 f8 8b 84 11 90 01 02 ff ff 03 45 14 8b 4d 18 8b 55 10 03 11 8b 4d f8 89 84 0a 90 01 02 ff ff e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}