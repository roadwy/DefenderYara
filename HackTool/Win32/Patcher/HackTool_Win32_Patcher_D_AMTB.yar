
rule HackTool_Win32_Patcher_D_AMTB{
	meta:
		description = "HackTool:Win32/Patcher.D!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {52 45 56 45 4e 47 45 20 43 72 65 77 20 43 72 61 63 6b } //REVENGE Crew Crack  1
		$a_80_1 = {52 65 67 69 73 74 72 79 20 70 61 74 63 68 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 } //Registry patched successfully!  1
		$a_80_2 = {53 68 69 74 21 20 49 20 43 61 6e 27 74 20 6f 70 65 6e 20 74 61 72 67 65 74 20 66 69 6c 65 21 } //Shit! I Can't open target file!  1
		$a_80_3 = {4e 6f 77 2c 20 67 69 76 65 20 6d 65 20 66 69 6c 65 20 74 6f 20 70 65 6e 65 74 72 61 74 65 } //Now, give me file to penetrate  1
		$a_80_4 = {50 61 74 63 68 20 4f 4b 21 20 45 6e 6a 6f 79 20 49 74 21 } //Patch OK! Enjoy It!  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}