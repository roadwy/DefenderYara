
rule Trojan_Win32_Tedy_GK_MTB{
	meta:
		description = "Trojan:Win32/Tedy.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 32 2e 65 78 65 } //01 00  C:\Users\Public\2.exe
		$a_81_1 = {43 3a 5c 55 73 65 72 73 5c 77 65 67 61 6d 65 2e 65 78 65 } //01 00  C:\Users\wegame.exe
		$a_81_2 = {68 74 74 70 3a 2f 2f 31 36 34 2e 31 35 35 2e 32 35 35 2e 38 31 2f 32 2e 65 78 65 } //01 00  http://164.155.255.81/2.exe
		$a_81_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6c 69 62 63 65 66 2e 64 6c 6c } //01 00  C:\Users\Public\libcef.dll
		$a_81_4 = {68 74 74 70 3a 2f 2f 31 36 34 2e 31 35 35 2e 32 35 35 2e 38 31 2f 6c 69 62 63 65 66 2e 64 6c 6c } //00 00  http://164.155.255.81/libcef.dll
	condition:
		any of ($a_*)
 
}