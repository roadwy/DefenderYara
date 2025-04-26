
rule Trojan_Win32_Miniduke_GHC_MTB{
	meta:
		description = "Trojan:Win32/Miniduke.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 0f b6 40 35 8b 4d 0c 0f b6 49 35 33 d2 3b c1 0f 9c c2 88 55 ff 8a 45 ff c9 c3 } //10
		$a_80_1 = {42 71 77 65 72 74 79 75 69 6f 70 61 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d } //Bqwertyuiopasdfghjklzxcvbnm  1
		$a_80_2 = {6a 61 76 61 63 63 2e 65 78 65 } //javacc.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}