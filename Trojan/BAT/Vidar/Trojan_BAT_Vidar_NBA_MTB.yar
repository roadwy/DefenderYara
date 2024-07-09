
rule Trojan_BAT_Vidar_NBA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 04 11 07 1f 40 12 01 6f ?? ?? ?? 06 13 05 20 ?? ?? ?? 00 28 ?? ?? ?? 06 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 00 05 8e 69 13 07 } //5
		$a_01_1 = {56 49 6d 6a 4c 77 67 30 59 } //1 VImjLwg0Y
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}