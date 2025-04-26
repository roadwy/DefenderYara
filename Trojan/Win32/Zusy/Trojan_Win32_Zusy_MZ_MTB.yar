
rule Trojan_Win32_Zusy_MZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_81_0 = {25 75 73 65 72 61 70 70 64 61 74 61 25 5c 52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } //2 %userappdata%\RestartApp.exe
		$a_81_1 = {62 6d 71 61 7a 7a 78 6c } //2 bmqazzxl
		$a_81_2 = {64 65 66 4f 66 66 2e 65 78 65 } //2 defOff.exe
		$a_81_3 = {73 78 65 75 75 73 69 74 } //1 sxeuusit
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1) >=7
 
}