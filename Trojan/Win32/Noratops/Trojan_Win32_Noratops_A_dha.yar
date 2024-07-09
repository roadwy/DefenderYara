
rule Trojan_Win32_Noratops_A_dha{
	meta:
		description = "Trojan:Win32/Noratops.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 fa 40 7c ?? a8 03 0f 85 ?? ?? ?? ?? 8b d0 c1 ea 02 6a 3d 6b d2 03 } //1
		$a_01_1 = {7e 00 24 00 63 00 6f 00 6d 00 2e 00 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 64 00 65 00 62 00 75 00 67 00 2e 00 74 00 6d 00 70 00 } //1 ~$com.firefox.debug.tmp
		$a_00_2 = {49 6e 6a 65 63 74 6f 72 2e 64 6c 6c } //1 Injector.dll
		$a_03_3 = {6a 02 53 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? bf 6c 0e 00 00 83 c4 10 3b c7 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=100
 
}