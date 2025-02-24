
rule Trojan_Win32_KillWin_NH_MTB{
	meta:
		description = "Trojan:Win32/KillWin.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 04 24 88 13 00 00 a1 dc 62 48 00 ff d0 83 ec 04 c7 04 24 d4 da 47 00 e8 c3 f9 00 00 b8 00 00 00 00 8b 4d fc } //3
		$a_01_1 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete Shadows /all /quiet
		$a_01_2 = {64 65 6c 20 25 68 6f 6d 65 64 72 69 76 65 25 5c 4e 54 44 45 54 45 43 54 2e 43 4f 4d } //1 del %homedrive%\NTDETECT.COM
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}