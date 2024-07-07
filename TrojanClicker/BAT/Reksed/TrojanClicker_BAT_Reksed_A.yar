
rule TrojanClicker_BAT_Reksed_A{
	meta:
		description = "TrojanClicker:BAT/Reksed.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 22 00 69 00 64 00 73 00 5c 00 22 00 3a 00 5c 00 73 00 2a 00 5c 00 5b 00 5c 00 73 00 2a 00 } //1 \"ids\":\s*\[\s*
		$a_01_1 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 5c 00 } //1 Google\Chrome\User Data\Default\Extensions\
		$a_01_2 = {5c 00 73 00 65 00 64 00 61 00 74 00 2e 00 6a 00 73 00 } //1 \sedat.js
		$a_01_3 = {00 67 65 74 5f 53 65 64 61 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}