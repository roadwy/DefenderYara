
rule Trojan_BAT_Redline_GTT_MTB{
	meta:
		description = "Trojan:BAT/Redline.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 5b 00 00 70 0a 06 28 90 01 03 0a 0b 28 90 01 03 0a 07 16 07 8e 69 6f 90 01 03 0a 0a 28 90 01 03 0a 06 6f 90 01 03 0a 0c 1f 61 6a 08 90 00 } //10
		$a_01_1 = {61 00 57 00 31 00 77 00 62 00 33 00 4a 00 30 00 4c 00 6d 00 70 00 68 00 64 00 6d 00 45 00 75 00 64 00 58 00 52 00 70 00 62 00 43 00 35 00 79 00 5a 00 57 00 64 00 6c 00 65 00 43 00 35 00 4e 00 59 00 58 00 } //1 aW1wb3J0LmphdmEudXRpbC5yZWdleC5NYX
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}