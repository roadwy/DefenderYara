
rule TrojanDropper_Win32_Fakefire_B{
	meta:
		description = "TrojanDropper:Win32/Fakefire.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_00_0 = {4d 61 63 49 6e 73 74 61 6c 6c 65 72 } //1 MacInstaller
		$a_00_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 56 00 69 00 73 00 75 00 61 00 6c 00 20 00 53 00 74 00 75 00 64 00 69 00 6f 00 5c 00 56 00 42 00 39 00 38 00 5c 00 70 00 6a 00 74 00 41 00 77 00 73 00 56 00 61 00 72 00 69 00 61 00 6e 00 74 00 69 00 6f 00 6e 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //1 C:\Program Files\Microsoft Visual Studio\VB98\pjtAwsVariantioner.vbp
		$a_00_2 = {4d 00 53 00 46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 } //1 MSFirewall
		$a_00_3 = {43 00 3a 00 5c 00 56 00 42 00 56 00 69 00 72 00 75 00 73 00 5c 00 46 00 75 00 63 00 6b 00 59 00 6f 00 75 00 2e 00 70 00 74 00 74 00 } //1 C:\VBVirus\FuckYou.ptt
		$a_00_4 = {5c 00 53 00 65 00 74 00 31 00 2e 00 49 00 63 00 6f 00 } //1 \Set1.Ico
		$a_00_5 = {5c 00 42 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 2e 00 65 00 78 00 65 00 } //1 \BProtect.exe
		$a_00_6 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 } //1 wscript.Shell
		$a_00_7 = {48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_02_8 = {8b c4 8b 4d ac 89 08 8b 55 b0 89 50 04 8b 4d b4 89 48 08 8b 55 b8 89 50 0c 68 ?? ?? 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 8b d0 8d 4d cc ff 15 ?? ?? 40 00 8b d0 8b 4d 08 83 c1 40 ff 15 ?? ?? 40 00 8d 4d cc ff 15 ?? ?? 40 00 c7 45 fc 05 00 00 00 6a 00 68 ?? ?? 40 00 8d 45 bc 50 ff 15 ?? ?? 40 00 8d 4d bc 51 8d 55 d0 52 ff 15 ?? ?? 40 00 c7 45 fc 06 00 00 00 68 ?? ?? 40 00 8b 45 08 8b 48 38 51 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_02_8  & 1)*1) >=9
 
}