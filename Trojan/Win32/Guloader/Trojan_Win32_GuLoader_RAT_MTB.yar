
rule Trojan_Win32_GuLoader_RAT_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {75 6e 64 65 72 6f 70 64 65 6c 65 6e 64 65 73 20 63 6f 75 6e 74 65 72 74 72 65 61 73 6f 6e 20 69 6e 74 65 6e 73 69 76 65 72 69 6e 67 } //1 underopdelendes countertreason intensivering
		$a_81_1 = {73 76 61 6e 65 73 61 6e 67 20 73 65 63 74 61 72 69 61 6c } //1 svanesang sectarial
		$a_81_2 = {64 69 73 61 75 67 6d 65 6e 74 20 74 68 72 75 6d 6d 65 64 2e 65 78 65 } //1 disaugment thrummed.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}