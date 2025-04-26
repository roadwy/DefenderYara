
rule HackTool_BAT_BruteForce_ARA_MTB{
	meta:
		description = "HackTool:BAT/BruteForce.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 6e 65 72 61 74 65 50 61 73 73 77 6f 72 64 } //2 GeneratePassword
		$a_01_1 = {42 72 75 74 65 52 75 6e 6e 65 72 } //2 BruteRunner
		$a_01_2 = {43 6f 6e 76 65 72 74 54 6f 42 61 73 65 36 34 } //2 ConvertToBase64
		$a_00_3 = {6d 00 61 00 69 00 6c 00 73 00 2e 00 74 00 78 00 74 00 } //1 mails.txt
		$a_00_4 = {50 00 72 00 6f 00 78 00 69 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //1 Proxies.txt
		$a_00_5 = {52 00 65 00 6d 00 61 00 69 00 6e 00 69 00 6e 00 67 00 20 00 43 00 6f 00 6d 00 62 00 6f 00 2e 00 74 00 78 00 74 00 } //1 Remaining Combo.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=8
 
}