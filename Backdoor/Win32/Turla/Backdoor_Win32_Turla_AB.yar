
rule Backdoor_Win32_Turla_AB{
	meta:
		description = "Backdoor:Win32/Turla.AB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 6a 65 63 74 73 5c 63 75 73 70 69 64 50 6f 77 65 72 73 68 65 6c 6c 5c 63 75 73 70 69 64 5c 45 6d 62 65 64 64 65 64 44 6c 6c 73 5c 41 4d 53 49 46 69 6e 64 65 72 5c 41 4d 53 49 46 69 6e 64 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 41 4d 53 49 46 69 6e 64 65 72 2e 70 64 62 } //1 c:\projects\cuspidPowershell\cuspid\EmbeddedDlls\AMSIFinder\AMSIFinder\obj\Release\AMSIFinder.pdb
		$a_01_1 = {64 63 37 37 32 62 34 63 2d 65 32 36 32 2d 34 37 61 37 2d 61 39 35 36 2d 61 63 36 61 32 62 30 38 66 38 31 36 } //1 dc772b4c-e262-47a7-a956-ac6a2b08f816
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}