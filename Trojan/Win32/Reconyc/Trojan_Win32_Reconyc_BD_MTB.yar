
rule Trojan_Win32_Reconyc_BD_MTB{
	meta:
		description = "Trojan:Win32/Reconyc.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8b 55 f8 8a 5c 10 ff 80 f3 0a 8d 45 f4 8b d3 e8 90 02 04 8b 55 f4 8b c7 e8 90 02 04 ff 45 f8 4e 75 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00 
		$a_01_2 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}