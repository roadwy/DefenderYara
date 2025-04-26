
rule Trojan_Win32_Delf_OKN_MTB{
	meta:
		description = "Trojan:Win32/Delf.OKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {23 c2 c1 e0 03 01 45 f4 8b 4d f4 33 c0 8a 01 89 45 f0 85 c0 } //4
		$a_81_1 = {25 54 45 4d 50 25 5c 53 79 6e 63 43 6c 69 70 52 6f 6f 74 5c } //1 %TEMP%\SyncClipRoot\
		$a_81_2 = {25 54 45 4d 50 25 5c 76 6d 77 61 72 65 } //1 %TEMP%\vmware
	condition:
		((#a_01_0  & 1)*4+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=6
 
}