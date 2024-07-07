
rule Trojan_BAT_BatLaunch_RPY_MTB{
	meta:
		description = "Trojan:BAT/BatLaunch.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 00 69 00 64 00 65 00 69 00 74 00 2e 00 62 00 61 00 74 00 } //1 hideit.bat
		$a_01_1 = {72 65 6d 20 47 4f 20 47 4f 20 47 4f } //1 rem GO GO GO
		$a_01_2 = {74 69 6d 65 6f 75 74 20 2f 74 20 31 30 20 2f 6e 6f 62 72 65 61 6b } //1 timeout /t 10 /nobreak
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 } //1 powershell -command
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 } //1 DownloadFile(
		$a_01_5 = {74 72 61 6e 73 66 65 72 2e 73 68 } //1 transfer.sh
		$a_01_6 = {53 45 52 56 45 52 2e 65 78 65 } //1 SERVER.exe
		$a_01_7 = {73 74 61 72 74 20 2f 62 20 73 76 63 2e 65 78 65 } //1 start /b svc.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}