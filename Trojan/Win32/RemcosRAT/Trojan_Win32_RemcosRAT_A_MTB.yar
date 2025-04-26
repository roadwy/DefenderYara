
rule Trojan_Win32_RemcosRAT_A_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 64 72 6c 61 76 69 68 38 } //2 hdrlavih8
		$a_01_1 = {73 74 72 6c 73 74 72 68 38 } //2 strlstrh8
		$a_01_2 = {76 69 64 73 52 4c 45 } //2 vidsRLE
		$a_01_3 = {56 61 4c 5f 64 31 50 59 } //2 VaL_d1PY
		$a_01_4 = {63 6d 64 20 2f 63 20 63 6d 64 20 3c 20 50 72 65 66 65 72 65 6e 63 65 73 2e 76 73 64 20 26 20 70 69 6e 67 20 2d 6e 20 35 20 6c 6f 63 61 6c 68 6f 73 74 } //2 cmd /c cmd < Preferences.vsd & ping -n 5 localhost
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}
rule Trojan_Win32_RemcosRAT_A_MTB_2{
	meta:
		description = "Trojan:Win32/RemcosRAT.A!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //10 net.webclient
		$a_00_1 = {5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 72 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 5d 00 3a 00 3a 00 6c 00 6f 00 61 00 64 00 28 00 24 00 } //10 [system.reflection.assembly]::load($
		$a_00_2 = {2e 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 28 00 24 00 } //10 .invoke($
		$a_00_3 = {68 00 74 00 74 00 70 00 } //10 http
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}