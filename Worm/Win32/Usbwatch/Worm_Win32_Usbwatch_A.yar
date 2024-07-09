
rule Worm_Win32_Usbwatch_A{
	meta:
		description = "Worm:Win32/Usbwatch.A,SIGNATURE_TYPE_PEHSTR_EXT,72 01 68 01 09 00 00 "
		
	strings :
		$a_00_0 = {55 53 42 57 41 54 43 48 50 52 4f } //100 USBWATCHPRO
		$a_00_1 = {55 00 53 00 42 00 57 00 41 00 54 00 43 00 48 00 50 00 52 00 4f 00 } //100 USBWATCHPRO
		$a_00_2 = {25 73 5c 41 75 74 6f 52 75 6e 2e 69 6e 66 } //100 %s\AutoRun.inf
		$a_00_3 = {5c 53 45 52 56 49 43 45 53 2e 45 58 45 } //10 \SERVICES.EXE
		$a_00_4 = {25 53 79 73 74 65 6d 44 72 69 76 65 25 5c 52 65 63 79 63 6c 65 64 5c } //10 %SystemDrive%\Recycled\
		$a_00_5 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e } //10 ShowSuperHidden
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 } //10 Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
		$a_02_7 = {83 f8 02 59 89 45 f4 0f 8c f7 02 00 00 8d 85 ?? ?? ff ff c7 45 ?? 01 00 00 00 50 8d 85 ?? ?? ff ff 68 ?? ?? 40 00 50 ff d3 83 c4 0c 8d 85 ?? ?? ff ff 57 50 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 8d 85 ?? ?? ff ff 6a 00 50 ff 15 ?? ?? 40 00 8d 85 d4 f6 ff ff 50 8d 85 ?? ?? ff ff 68 ?? ?? 40 00 50 ff d3 8b 1d ?? ?? 40 00 83 c4 0c 8d 85 ?? ?? ff ff 68 80 00 00 00 50 ff d3 8d 85 ?? ?? ff ff 6a 00 50 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? 40 00 85 c0 } //30
		$a_02_8 = {68 00 01 00 00 51 ff 15 ?? ?? 40 00 bf ?? ?? 40 00 83 c9 ff 33 c0 8d 94 24 ?? ?? 00 00 f2 ae f7 d1 2b f9 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 84 24 ?? ?? 00 00 83 e1 03 50 f3 a4 8d [0-06] 51 e8 ?? ?? ff ff 83 c4 08 8d [0-06] 6a 00 52 ff 15 } //30
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_02_7  & 1)*30+(#a_02_8  & 1)*30) >=360
 
}