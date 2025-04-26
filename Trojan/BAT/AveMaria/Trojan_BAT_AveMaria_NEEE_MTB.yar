
rule Trojan_BAT_AveMaria_NEEE_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 65 65 34 61 36 66 66 2d 39 65 36 34 2d 34 32 34 64 2d 38 66 39 37 2d 66 65 37 33 64 36 66 64 30 32 66 30 } //5 bee4a6ff-9e64-424d-8f97-fe73d6fd02f0
		$a_01_1 = {43 61 6c 63 75 6c 61 74 6f 72 2e 65 78 65 } //2 Calculator.exe
		$a_01_2 = {45 6d 69 6c 20 53 61 79 61 68 69 } //2 Emil Sayahi
		$a_01_3 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //2 get_ExecutablePath
		$a_01_4 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //1 RPF:SmartAssembly
		$a_01_5 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_6 = {4d 79 2e 4d 79 50 72 6f 6a 65 63 74 2e 46 6f 72 6d 73 } //1 My.MyProject.Forms
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=14
 
}