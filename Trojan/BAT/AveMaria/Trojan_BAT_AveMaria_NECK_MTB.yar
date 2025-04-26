
rule Trojan_BAT_AveMaria_NECK_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {18 16 2c 4b 26 2b 32 06 07 9a 16 2c 45 26 08 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 28 03 00 00 0a 33 0a 17 25 } //10
		$a_01_1 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } //5 SmartAssembly.HouseOfCards
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}