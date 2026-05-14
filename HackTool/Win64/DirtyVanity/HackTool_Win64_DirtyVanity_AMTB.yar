
rule HackTool_Win64_DirtyVanity_AMTB{
	meta:
		description = "HackTool:Win64/DirtyVanity!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 77 72 6f 74 65 20 73 68 65 6c 6c 63 6f 64 65 20 74 6f 20 76 69 63 74 69 6d 2e 20 41 62 6f 75 74 20 74 6f 20 73 74 61 72 74 20 74 68 65 20 4d 69 72 72 6f 72 69 6e 67 } //Successfully wrote shellcode to victim. About to start the Mirroring  2
		$a_80_1 = {44 69 72 74 79 56 61 6e 69 74 79 20 5b 54 41 52 47 45 54 5f 50 49 44 5f 54 4f 5f 52 45 46 4c 45 43 54 5d } //DirtyVanity [TARGET_PID_TO_REFLECT]  2
		$a_80_2 = {44 69 72 74 79 5f 56 61 6e 69 74 79 2e 70 64 62 } //Dirty_Vanity.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=3
 
}