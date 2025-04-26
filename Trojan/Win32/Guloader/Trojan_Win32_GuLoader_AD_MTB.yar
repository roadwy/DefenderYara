
rule Trojan_Win32_GuLoader_AD_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 59 4e 42 4f 45 4e 41 43 43 49 44 } //FYNBOENACCID  3
		$a_80_1 = {70 6f 6c 79 70 73 79 63 } //polypsyc  3
		$a_80_2 = {62 72 6e 64 65 73 6b } //brndesk  3
		$a_80_3 = {42 61 61 6e 64 6f 70 74 61 67 65 72 65 73 68 61 72 } //Baandoptagereshar  3
		$a_80_4 = {55 73 6b 61 64 65 6c 69 67 67 72 65 6c 73 65 72 6e } //Uskadeliggrelsern  3
		$a_80_5 = {53 71 75 69 72 6d 65 } //Squirme  3
		$a_80_6 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 41 64 64 52 65 66 } //EVENT_SINK_AddRef  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_GuLoader_AD_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_81_0 = {66 6c 6c 65 73 62 72 6e 2e 74 78 74 } //2 fllesbrn.txt
		$a_81_1 = {59 64 65 72 72 65 64 65 6e 73 31 30 32 2e 4b 61 6e } //2 Yderredens102.Kan
		$a_81_2 = {62 6c 69 6e 6b 65 6e 62 65 72 67 2e 74 78 74 } //2 blinkenberg.txt
		$a_81_3 = {63 69 76 69 6c 69 73 61 62 6c 65 5c 45 6e 74 65 72 6f 63 6f 63 63 69 31 34 33 } //2 civilisable\Enterococci143
		$a_81_4 = {6d 65 73 61 6c 6c 69 61 6e 63 65 72 73 5c 53 65 6b 73 61 61 72 69 6e 67 65 6e } //2 mesalliancers\Seksaaringen
		$a_81_5 = {63 68 65 67 6f 5c 72 65 76 65 72 65 6e 73 65 6e 73 } //2 chego\reverensens
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2) >=12
 
}
rule Trojan_Win32_GuLoader_AD_MTB_3{
	meta:
		description = "Trojan:Win32/GuLoader.AD!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 00 6f 00 74 00 31 00 33 00 2e 00 64 00 6c 00 6c 00 } //1 rot13.dll
		$a_01_1 = {63 00 72 00 6f 00 6f 00 6b 00 65 00 64 00 65 00 72 00 2e 00 69 00 6e 00 69 00 } //1 crookeder.ini
		$a_01_2 = {53 00 65 00 61 00 72 00 63 00 68 00 54 00 72 00 65 00 65 00 46 00 6f 00 72 00 46 00 69 00 6c 00 65 00 28 00 74 00 20 00 27 00 4c 00 49 00 4d 00 42 00 4f 00 55 00 53 00 27 00 2c 00 74 00 20 00 27 00 48 00 6f 00 74 00 73 00 70 00 6f 00 74 00 27 00 2c 00 6d 00 20 00 27 00 46 00 41 00 49 00 4e 00 54 00 4c 00 59 00 27 00 29 00 } //1 SearchTreeForFile(t 'LIMBOUS',t 'Hotspot',m 'FAINTLY')
		$a_01_3 = {77 00 69 00 67 00 77 00 61 00 6d 00 73 00 2e 00 69 00 6e 00 69 00 } //1 wigwams.ini
		$a_01_4 = {66 00 75 00 7a 00 7a 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //1 fuzzer.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_AD_MTB_4{
	meta:
		description = "Trojan:Win32/GuLoader.AD!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 00 7a 00 73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 74 00 2e 00 64 00 6c 00 6c 00 } //1 fzshellext.dll
		$a_01_1 = {45 00 64 00 64 00 69 00 65 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2d 00 45 00 6c 00 65 00 76 00 61 00 74 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 Eddie-Service-Elevated.exe
		$a_01_2 = {4d 00 70 00 43 00 6d 00 64 00 52 00 75 00 6e 00 2e 00 65 00 78 00 65 00 } //1 MpCmdRun.exe
		$a_01_3 = {43 00 6f 00 76 00 65 00 72 00 45 00 64 00 43 00 74 00 72 00 6c 00 2e 00 6d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 } //1 CoverEdCtrl.manifest
		$a_01_4 = {50 00 53 00 52 00 65 00 61 00 64 00 6c 00 69 00 6e 00 65 00 2e 00 70 00 73 00 } //1 PSReadline.ps
		$a_01_5 = {50 00 61 00 6e 00 65 00 6c 00 49 00 6e 00 66 00 6f 00 2e 00 64 00 6c 00 6c 00 } //1 PanelInfo.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}