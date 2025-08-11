
rule Trojan_Win32_Upatre_MR_MTB{
	meta:
		description = "Trojan:Win32/Upatre.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 8b 14 ?? ?? 30 40 00 29 c0 57 59 40 c1 e9 02 3b c8 76 } //20
		$a_01_1 = {83 4c 24 10 ff c7 44 24 34 18 21 40 00 c7 44 24 38 28 21 40 00 89 74 24 3c 89 74 24 20 89 74 24 14 } //10
		$a_01_2 = {32 1d 32 25 32 4a 32 5a 32 6a 32 } //1
		$a_01_3 = {43 3a 5c 54 45 4d 50 5c 67 66 66 6f 73 2e 65 78 65 } //1 C:\TEMP\gffos.exe
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=32
 
}