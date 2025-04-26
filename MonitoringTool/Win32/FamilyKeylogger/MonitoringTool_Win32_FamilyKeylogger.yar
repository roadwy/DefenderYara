
rule MonitoringTool_Win32_FamilyKeylogger{
	meta:
		description = "MonitoringTool:Win32/FamilyKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 46 61 6d 69 6c 79 20 4b 65 79 6c 6f 67 67 65 72 20 34 5c 46 61 6d 69 6c 79 20 4b 65 79 6c 6f 67 67 65 72 2e 6c 6e 6b } //3 \Family Keylogger 4\Family Keylogger.lnk
		$a_01_1 = {6d 61 69 6c 74 6f 3a 73 75 70 6f 72 74 40 73 70 79 61 72 73 65 6e 61 6c 2e 63 6f 6d 3f 73 75 62 6a 65 63 74 3d 46 4b 4c 34 } //5 mailto:suport@spyarsenal.com?subject=FKL4
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*5) >=8
 
}
rule MonitoringTool_Win32_FamilyKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/FamilyKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3c 64 69 76 20 63 6c 61 73 73 3d 22 77 69 6e 74 69 74 6c 65 22 3e 5b 25 30 32 64 2f 25 30 32 64 2f 25 30 34 64 2c 20 25 30 32 64 3a 25 30 32 64 5d 2e 20 20 20 55 73 65 72 3a 20 22 25 73 22 2e 20 20 57 69 6e 64 6f 77 20 74 69 74 6c 65 3a 22 25 73 22 3c 2f 64 69 76 3e } //1 <div class="wintitle">[%02d/%02d/%04d, %02d:%02d].   User: "%s".  Window title:"%s"</div>
		$a_03_1 = {63 3a 5c 74 65 6d 70 5c 74 65 6d 70 90 05 02 03 30 2d 39 2e 74 78 74 } //1
		$a_03_2 = {c7 05 0c 21 01 10 00 00 00 00 68 c0 a1 00 10 8d 8d 90 09 0e 00 80 bd 20 ?? ff ff 0d 75 ?? 83 fb 01 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? fe ff ff 51 ff 15 14 a0 00 10 68 00 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule MonitoringTool_Win32_FamilyKeylogger_3{
	meta:
		description = "MonitoringTool:Win32/FamilyKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 33 32 56 32 43 6f 6e 74 6f 6c 6c 65 72 } //1 Sys32V2Contoller
		$a_01_1 = {2d 6e 65 77 20 68 74 74 70 3a 2f 2f 73 70 79 61 72 73 65 6e 61 6c 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 72 65 67 2e 70 6c 3f 70 3d 66 6b 6c 26 6b 65 79 3d 25 73 26 76 3d 25 73 } //3 -new http://spyarsenal.com/cgi-bin/reg.pl?p=fkl&key=%s&v=%s
		$a_00_2 = {46 00 61 00 6d 00 69 00 6c 00 79 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 76 00 } //3 Family Keylogger v
		$a_01_3 = {3c 64 69 76 20 63 6c 61 73 73 3d 22 77 69 6e 74 69 74 6c 65 22 3e 5b 25 30 32 64 2f 25 30 32 64 2f 25 30 34 64 2c 20 25 30 32 64 3a 25 30 32 64 5d 2e 20 20 20 55 73 65 72 3a 20 22 25 73 22 2e 20 20 57 69 6e 64 6f 77 20 74 69 74 6c 65 3a 22 25 73 22 3c 2f 64 69 76 3e } //5 <div class="wintitle">[%02d/%02d/%04d, %02d:%02d].   User: "%s".  Window title:"%s"</div>
		$a_00_4 = {73 00 76 00 63 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 svcl32.dll
		$a_00_5 = {53 00 79 00 73 00 56 00 43 00 6f 00 6e 00 74 00 6f 00 6c 00 6c 00 65 00 72 00 33 00 32 00 } //1 SysVContoller32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_00_2  & 1)*3+(#a_01_3  & 1)*5+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}