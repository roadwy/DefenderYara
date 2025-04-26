
rule Trojan_Win32_Zbot_CB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 07 03 fb 03 02 89 02 03 d3 49 75 f3 } //2
		$a_01_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 61 00 64 00 6d 00 69 00 6e 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 5c 00 68 00 72 00 6f 00 6d 00 69 00 2e 00 65 00 78 00 65 00 } //1 C:\Users\admin\Downloads\hromi.exe
		$a_01_2 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 6d 00 61 00 78 00 69 00 6e 00 65 00 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 66 00 69 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //1 C:\Users\maxine\AppData\Local\Temp\file.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}