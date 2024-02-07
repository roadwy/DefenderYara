
rule Trojan_Win32_Resur_LK_MTB{
	meta:
		description = "Trojan:Win32/Resur.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 73 63 6f 6d 6d 61 6e 64 5c 5f 66 73 63 6d 64 5f 69 6e 73 74 31 2e 65 78 65 } //0a 00  fscommand\_fscmd_inst1.exe
		$a_01_1 = {46 6f 6c 64 65 72 5c 45 71 75 61 74 69 6f 6e 5c 4b 69 6c 6c 65 72 2e 65 78 65 } //01 00  Folder\Equation\Killer.exe
		$a_01_2 = {66 35 30 2e 65 78 65 } //01 00  f50.exe
		$a_01_3 = {4d 6f 75 73 65 4c 6f 63 61 74 6f 72 2e 45 58 45 } //01 00  MouseLocator.EXE
		$a_01_4 = {70 6c 75 73 6f 6e 65 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 5f 2f 2b 31 2f 63 6f 6e 66 69 72 6d 3f 68 6c 3d 65 6e 26 75 72 6c 3d 68 74 74 70 2f 2f 65 66 69 67 75 72 65 6f 75 74 2e 63 6f 6d } //00 00  plusone.google.com/_/+1/confirm?hl=en&url=http//efigureout.com
	condition:
		any of ($a_*)
 
}