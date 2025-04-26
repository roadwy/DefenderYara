
rule Trojan_Win32_Lenoplug_A{
	meta:
		description = "Trojan:Win32/Lenoplug.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 4c 65 6e 6f 76 6f 53 65 72 76 69 63 65 50 6c 75 67 69 6e 2e 64 6d 70 } //1 %s\LenovoServicePlugin.dmp
		$a_01_1 = {73 63 20 63 6f 6e 66 69 67 20 4c 65 6e 6f 76 6f 53 65 72 76 69 63 65 50 6c 75 67 69 6e 53 76 63 20 73 74 61 72 74 3d 20 61 75 74 6f } //1 sc config LenovoServicePluginSvc start= auto
		$a_01_2 = {6e 65 74 20 73 74 61 72 74 20 4c 65 6e 6f 76 6f 53 65 72 76 69 63 65 50 6c 75 67 69 6e 53 76 63 } //1 net start LenovoServicePluginSvc
		$a_01_3 = {52 45 47 20 41 44 44 20 48 4b 45 59 5f 43 4c 41 53 53 45 53 5f 52 4f 4f 54 5c 4c 65 6e 6f 76 6f 53 65 72 76 69 63 65 50 6c 75 67 69 6e 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 20 2f 76 20 22 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 5c 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4c 65 6e 6f 76 6f 49 68 64 5c 4c 65 6e 6f 76 6f 53 65 72 76 69 63 65 50 6c 75 67 69 6e 2e 65 78 65 5c 22 20 5c 22 25 31 5c 22 22 20 20 2f 66 } //1 REG ADD HKEY_CLASSES_ROOT\LenovoServicePlugin\shell\open\command /v "" /t REG_SZ /d "\"C:\ProgramData\LenovoIhd\LenovoServicePlugin.exe\" \"%1\""  /f
		$a_01_4 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 4c 00 65 00 6e 00 6f 00 76 00 6f 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 50 00 6c 00 75 00 67 00 69 00 6e 00 4d 00 61 00 69 00 6e 00 2e 00 65 00 78 00 65 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=5
 
}