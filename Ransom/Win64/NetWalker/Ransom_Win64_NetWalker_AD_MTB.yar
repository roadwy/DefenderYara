
rule Ransom_Win64_NetWalker_AD_MTB{
	meta:
		description = "Ransom:Win64/NetWalker.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {72 00 75 00 6e 00 61 00 73 00 } //1 runas
		$a_01_1 = {63 00 68 00 61 00 6e 00 67 00 65 00 70 00 6b 00 2e 00 65 00 78 00 65 00 } //1 changepk.exe
		$a_01_2 = {4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 2e 00 53 00 79 00 73 00 74 00 65 00 6d 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 } //1 Launcher.SystemSettings
		$a_01_3 = {73 00 74 00 61 00 72 00 74 00 } //1 start
		$a_01_4 = {6d 00 73 00 63 00 66 00 69 00 6c 00 65 00 } //1 mscfile
		$a_01_5 = {65 00 78 00 65 00 66 00 69 00 6c 00 65 00 } //1 exefile
		$a_01_6 = {6b 69 6c 6c } //1 kill
		$a_01_7 = {75 6e 6c 6f 63 6b } //1 unlock
		$a_01_8 = {77 68 69 74 65 } //1 white
		$a_01_9 = {73 76 63 77 61 69 74 } //1 svcwait
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}