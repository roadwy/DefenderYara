
rule Backdoor_Win32_Nucleroot_D{
	meta:
		description = "Backdoor:Win32/Nucleroot.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 75 74 65 71 71 2e 63 6e 2f 90 02 10 2e 65 78 65 90 00 } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 75 74 65 71 71 2e 63 6e 2f 3f 66 72 6f 6d 3d } //01 00  http://www.cuteqq.cn/?from=
		$a_00_2 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 77 77 77 63 75 74 65 71 71 63 6e 2c 27 20 2f 63 20 27 2b } //01 00  .ShellExecute(wwwcuteqqcn,' /c '+
		$a_03_3 = {89 4d fc c7 45 f8 90 01 04 c7 45 f4 90 01 04 c7 45 f0 90 01 04 c7 45 ec 90 01 04 68 90 01 04 68 90 01 04 e8 90 01 02 00 00 83 c4 08 89 45 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}