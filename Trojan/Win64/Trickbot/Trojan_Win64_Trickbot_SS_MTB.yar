
rule Trojan_Win64_Trickbot_SS_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 6c 6c 6f 72 2e 64 6c 6c } //1 dllor.dll
		$a_01_1 = {62 45 6a 76 76 67 46 37 7a 4c 53 56 65 37 49 } //1 bEjvvgF7zLSVe7I
		$a_01_2 = {53 4b 65 31 45 37 65 31 42 4a 6e 57 51 47 } //1 SKe1E7e1BJnWQG
		$a_01_3 = {30 71 6a 71 4f 53 64 6f 6e 6f 65 32 64 4c 55 57 } //1 0qjqOSdonoe2dLUW
		$a_00_4 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}