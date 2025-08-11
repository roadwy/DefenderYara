
rule Trojan_Win32_Qbot_BAA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 6f 75 6c 64 6e 27 74 20 6f 70 65 6e 20 74 68 65 20 66 69 6c 65 } //1 Couldn't open the file
		$a_81_1 = {40 65 63 68 6f 20 6f 66 66 } //1 @echo off
		$a_81_2 = {25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 73 6c 6d 67 72 2e 76 62 73 } //1 %windir%\system32\slmgr.vbs
		$a_81_3 = {6e 65 74 20 73 74 6f 70 20 44 50 53 } //1 net stop DPS
		$a_81_4 = {73 63 20 63 6f 6e 66 69 67 20 44 50 53 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 } //1 sc config DPS start= disabled
		$a_81_5 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 70 72 6f 66 69 6c 65 73 20 73 74 61 74 65 20 6f 66 66 76 69 73 75 61 } //1 netsh advfirewall set allprofiles state offvisua
		$a_81_6 = {40 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 73 68 65 6c 6c 33 32 2e 64 6c 6c } //1 @%SystemRoot%\system32\shell32.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}