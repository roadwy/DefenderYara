
rule Trojan_BAT_ClipBanker_SP_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 53 6e 6f 77 64 65 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 53 79 73 74 65 6d 54 65 78 74 50 72 6f 63 65 73 73 6f 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 53 79 73 74 65 6d 54 65 78 74 50 72 6f 63 65 73 73 6f 72 2e 70 64 62 } //2 C:\Users\Snowden\source\repos\SystemTextProcessor\obj\Release\SystemTextProcessor.pdb
		$a_81_1 = {53 79 73 74 65 6d 54 65 78 74 50 72 6f 63 65 73 73 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 SystemTextProcessor.Properties.Resources
		$a_81_2 = {53 79 73 74 65 6d 54 65 78 74 50 72 6f 63 65 73 73 6f 72 2e 65 78 65 } //2 SystemTextProcessor.exe
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}