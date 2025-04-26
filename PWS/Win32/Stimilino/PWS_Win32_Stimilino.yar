
rule PWS_Win32_Stimilino{
	meta:
		description = "PWS:Win32/Stimilino,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5f 53 74 65 61 6c 4c 6f 67 2e 74 78 74 } //2 _StealLog.txt
		$a_01_1 = {5c 53 74 65 61 6c 5c 52 65 6c 65 61 73 65 5c 53 74 65 61 6c } //1 \Steal\Release\Steal
		$a_01_2 = {6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 } //1 loginusers.vdf
		$a_01_3 = {63 6f 6e 66 69 67 5c 53 74 65 61 6d 41 70 70 44 61 74 61 2e 76 64 66 } //1 config\SteamAppData.vdf
		$a_01_4 = {6e 6f 64 65 30 2e 6e 65 74 32 66 74 70 2e 72 75 } //1 node0.net2ftp.ru
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 53 74 65 61 6d 2e 65 78 65 } //1 taskkill /f /im Steam.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}