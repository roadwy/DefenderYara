
rule Backdoor_Win32_Morix_I{
	meta:
		description = "Backdoor:Win32/Morix.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6d 6f 7a 68 65 55 70 64 61 74 65 } //1 mozheUpdate
		$a_03_1 = {f3 ab 6a 00 c6 45 f4 51 c6 45 f5 33 c6 45 f6 36 c6 45 f7 30 c6 45 f8 53 c6 45 f9 44 c6 45 fa 43 c6 45 fb 6c c6 45 fc 61 c6 45 fd 73 c6 45 fe 73 66 ab ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 50 ff d6 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}