
rule Trojan_Win32_Zusy_AHD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 8b 45 fc 01 d0 0f b6 00 32 45 ec 89 c1 8b 55 14 8b 45 fc 01 d0 89 ca 88 10 83 45 fc 01 } //3
		$a_03_1 = {ff ff 76 c7 45 f0 09 00 00 00 8d 85 ?? ?? ff ff 89 44 24 0c c7 44 24 08 37 00 00 00 8b 45 f0 89 44 24 04 8d 85 ?? ?? ff ff 89 04 24 e8 } //2
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 43 20 74 69 6d 65 6f 75 74 20 2f 54 20 31 20 2f 4e 4f 42 52 45 41 4b 20 3e 6e 75 6c } //1 cmd.exe /C timeout /T 1 /NOBREAK >nul
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}