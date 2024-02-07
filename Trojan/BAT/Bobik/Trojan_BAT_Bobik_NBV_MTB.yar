
rule Trojan_BAT_Bobik_NBV_MTB{
	meta:
		description = "Trojan:BAT/Bobik.NBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {06 09 9a 28 15 00 00 0a 8e 2c 02 17 0b 09 17 58 0d 09 06 8e 69 32 e9 } //01 00 
		$a_01_1 = {73 70 6c 61 74 73 68 6f 74 2e 65 78 65 } //00 00  splatshot.exe
	condition:
		any of ($a_*)
 
}