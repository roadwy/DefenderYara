
rule VirTool_BAT_Obfuscator_AL{
	meta:
		description = "VirTool:BAT/Obfuscator.AL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 50 61 73 73 50 68 72 61 73 65 00 5f 70 61 73 73 50 68 72 61 73 65 53 74 72 65 6e 67 74 68 00 5f 53 61 6c 74 56 61 6c 75 65 00 } //1
		$a_03_1 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 00 44 6c 6c 49 6d 70 6f 72 74 41 74 74 72 69 62 75 74 65 00 [0-20] 2e 64 6c 6c 00 } //1
		$a_01_2 = {54 68 65 20 73 61 6c 74 20 76 61 6c 75 65 20 75 73 65 64 20 74 6f 20 66 6f 69 6c 20 68 61 63 6b 65 72 73 20 61 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 63 72 61 63 6b 20 74 68 65 20 65 6e 63 72 79 70 74 69 6f 6e } //1 The salt value used to foil hackers attempting to crack the encryption
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}