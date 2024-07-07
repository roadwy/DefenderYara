
rule Backdoor_Win32_Lobparck_A{
	meta:
		description = "Backdoor:Win32/Lobparck.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 56 45 52 3d 43 6f 62 72 61 20 31 2e 32 26 4d 41 52 4b 3d } //1 &VER=Cobra 1.2&MARK=
		$a_01_1 = {70 72 6f 63 2f 69 6e 64 65 78 32 31 2e 70 68 70 20 48 54 54 50 2f 31 2e 31 } //1 proc/index21.php HTTP/1.1
		$a_01_2 = {25 73 5c 79 61 6d 6f 6f 6b 2e 65 78 65 } //1 %s\yamook.exe
		$a_01_3 = {6c 70 6b 2e 64 6c 6c } //1 lpk.dll
		$a_01_4 = {4d 65 6d 43 6f 64 65 5f 4c 70 6b 44 6c 6c 49 6e 69 74 69 61 6c 69 7a 65 } //1 MemCode_LpkDllInitialize
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}