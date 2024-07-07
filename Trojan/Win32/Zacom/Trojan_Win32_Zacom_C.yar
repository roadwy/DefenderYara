
rule Trojan_Win32_Zacom_C{
	meta:
		description = "Trojan:Win32/Zacom.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 45 47 20 41 44 44 20 48 4b 43 55 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e 20 2f 74 20 52 45 47 5f 45 58 50 41 4e 44 5f 53 5a 20 2f 76 20 6d 73 6e 65 74 62 72 69 64 67 65 20 2f 66 20 2f 64 20 22 25 73 22 } //1 REG ADD HKCU\software\microsoft\windows\currentversion\run /t REG_EXPAND_SZ /v msnetbridge /f /d "%s"
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 53 6f 75 6e 64 4f 46 5c 44 65 73 6b 74 6f 70 5c 61 76 65 6f 5c 52 65 6c 65 61 73 65 5c 61 76 65 6f 2e 70 64 62 } //1 C:\Users\SoundOF\Desktop\aveo\Release\aveo.pdb
		$a_01_2 = {69 6e 64 65 78 2e 70 68 70 3f 69 64 3d 33 35 34 37 31 26 31 3d 25 73 26 39 3d 25 73 } //1 index.php?id=35471&1=%s&9=%s
		$a_01_3 = {69 6e 64 65 78 2e 70 68 70 3f 69 64 3d 33 35 34 36 39 26 31 3d 25 73 26 39 3d 25 73 } //1 index.php?id=35469&1=%s&9=%s
		$a_01_4 = {63 6d 64 20 2f 63 20 63 6f 70 79 20 22 25 73 22 20 22 25 73 22 } //1 cmd /c copy "%s" "%s"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}