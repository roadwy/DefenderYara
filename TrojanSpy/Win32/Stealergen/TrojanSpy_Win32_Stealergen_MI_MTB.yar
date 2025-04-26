
rule TrojanSpy_Win32_Stealergen_MI_MTB{
	meta:
		description = "TrojanSpy:Win32/Stealergen.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 3d 74 d1 48 00 00 0f 84 ?? ?? ?? ?? 83 ec 08 0f ae 5c 24 04 8b 44 24 04 25 80 1f 00 00 3d 80 1f 00 00 75 ?? d9 3c 24 66 8b 04 24 66 83 e0 7f 66 83 f8 7f 8d 64 24 08 75 ?? e9 } //1
		$a_01_1 = {74 65 73 74 34 5c 65 31 30 34 5c 52 65 6c 65 61 73 65 5c 65 31 30 34 2e 70 64 62 } //1 test4\e104\Release\e104.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}