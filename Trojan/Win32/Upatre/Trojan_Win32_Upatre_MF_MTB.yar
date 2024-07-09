
rule Trojan_Win32_Upatre_MF_MTB{
	meta:
		description = "Trojan:Win32/Upatre.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 75 fc 68 ?? ?? ?? ?? ff 75 fc ff 15 ?? ?? ?? ?? 83 c4 10 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 53 ff 15 } //1
		$a_01_1 = {3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 62 00 75 00 64 00 68 00 61 00 2e 00 65 00 78 00 65 00 } //1 :\TEMP\budha.exe
		$a_01_2 = {6b 00 69 00 6c 00 66 00 2e 00 65 00 78 00 65 00 } //1 kilf.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}