
rule Trojan_Win64_ShellcodeInject_RFAK_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.RFAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 78 70 65 72 69 65 6e 63 65 2e 62 69 6e } //1 /xperience.bin
		$a_81_1 = {78 70 63 73 2e 74 6f 6f 6c 73 } //1 xpcs.tools
		$a_81_2 = {6e 6f 74 65 70 61 64 2e 65 78 65 } //1 notepad.exe
		$a_01_3 = {61 6c 66 52 65 6d 6f 74 65 4c 6f 61 64 65 72 2e 70 64 62 } //1 alfRemoteLoader.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}