
rule TrojanDropper_Win32_Sefnit_L{
	meta:
		description = "TrojanDropper:Win32/Sefnit.L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 25 5c 64 66 72 67 } //1 %%\dfrg
		$a_01_1 = {5c 73 76 63 2e 65 78 65 22 20 2d 69 } //1 \svc.exe" -i
		$a_01_2 = {5c 72 75 6e 6e 65 72 2e 65 78 65 } //1 \runner.exe
		$a_01_3 = {25 25 5c 5f 5f 74 65 73 74 } //1 %%\__test
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}