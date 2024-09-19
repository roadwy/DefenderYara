
rule Trojan_BAT_Redline_GTT_MTB{
	meta:
		description = "Trojan:BAT/Redline.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 24 11 47 5b 13 29 16 13 4c 2b 39 11 38 11 30 58 13 32 16 13 4d 2b 1e 11 45 11 44 61 13 1d 11 22 11 41 5a 13 37 11 30 6e 11 20 6a 61 6d 13 27 11 4d 17 58 13 4d 11 4d 20 ?? ?? ?? ?? 32 d9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_Redline_GTT_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 5b 00 00 70 0a 06 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 07 16 07 8e 69 6f ?? ?? ?? 0a 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0c 1f 61 6a 08 } //10
		$a_01_1 = {61 00 57 00 31 00 77 00 62 00 33 00 4a 00 30 00 4c 00 6d 00 70 00 68 00 64 00 6d 00 45 00 75 00 64 00 58 00 52 00 70 00 62 00 43 00 35 00 79 00 5a 00 57 00 64 00 6c 00 65 00 43 00 35 00 4e 00 59 00 58 00 } //1 aW1wb3J0LmphdmEudXRpbC5yZWdleC5NYX
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}