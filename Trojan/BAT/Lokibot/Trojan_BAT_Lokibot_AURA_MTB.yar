
rule Trojan_BAT_Lokibot_AURA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AURA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 0e 02 11 0b 11 0d 6f ?? 00 00 0a 7d ?? 00 00 04 11 0e 04 11 0e 7b ?? 00 00 04 7b ?? 00 00 04 6f ?? 00 00 0a 59 7d ?? 00 00 04 11 17 } //5
		$a_03_1 = {01 25 16 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c 25 17 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c 25 18 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c } //2
		$a_01_2 = {41 73 73 69 67 6e 6d 65 6e 74 32 5f 57 69 6e 66 6f 72 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 Assignment2_Winform.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}