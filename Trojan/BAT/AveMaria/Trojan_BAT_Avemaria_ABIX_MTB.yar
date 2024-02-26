
rule Trojan_BAT_Avemaria_ABIX_MTB{
	meta:
		description = "Trojan:BAT/Avemaria.ABIX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 00 02 6f 90 01 03 06 6f 90 01 03 0a 00 02 6f 90 01 03 06 6f 90 01 03 0a 00 2a 90 0a 35 00 72 90 01 03 70 0a 28 90 01 03 06 6f 90 01 03 0a 72 90 01 03 70 06 6f 90 00 } //01 00 
		$a_01_1 = {67 00 61 00 67 00 6f 00 67 00 61 00 6f 00 67 00 6f 00 61 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  gagogaogoa.Resources
		$a_01_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 49 00 4d 00 20 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //00 00  cmd.exe taskkill /IM cmd.exe
	condition:
		any of ($a_*)
 
}