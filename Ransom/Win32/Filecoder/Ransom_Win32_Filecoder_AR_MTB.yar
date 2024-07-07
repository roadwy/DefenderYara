
rule Ransom_Win32_Filecoder_AR_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //10 vssadmin delete shadows /all /quiet
		$a_81_1 = {5c 52 45 53 54 4f 52 45 5f 44 4c 4c 5f 46 49 4c 45 53 2e 48 54 4d 4c } //10 \RESTORE_DLL_FILES.HTML
		$a_81_2 = {5c 64 65 6c 65 74 65 2e 62 61 74 } //10 \delete.bat
		$a_81_3 = {54 68 72 65 61 74 45 78 70 65 72 74 20 53 75 63 6b 73 21 } //1 ThreatExpert Sucks!
		$a_81_4 = {22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //1 " goto Repeat
		$a_81_5 = {52 61 6e 73 6f 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Ransom.Properties.Resources
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=31
 
}