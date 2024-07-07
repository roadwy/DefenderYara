
rule Backdoor_BAT_NanoCoreRAT_A_MTB{
	meta:
		description = "Backdoor:BAT/NanoCoreRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {06 0b 07 6f 90 01 01 00 00 0a 17 da 0c 16 0d 2b 90 01 01 7e 90 01 01 00 00 04 07 09 16 6f 90 01 01 00 00 0a 13 90 01 01 12 90 01 01 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 09 17 d6 0d 09 08 31 90 00 } //1
		$a_01_1 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_2 = {46 72 6f 6d 53 74 72 65 61 6d } //1 FromStream
		$a_01_3 = {53 6c 65 65 70 } //1 Sleep
		$a_01_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_6 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}