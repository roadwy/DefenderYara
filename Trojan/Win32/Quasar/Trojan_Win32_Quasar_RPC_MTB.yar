
rule Trojan_Win32_Quasar_RPC_MTB{
	meta:
		description = "Trojan:Win32/Quasar.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 62 72 6f 77 73 65 72 5f 66 6f 6c 64 65 72 73 } //1 $browser_folders
		$a_01_1 = {53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 } //1 System.Net.WebClient
		$a_01_2 = {55 53 45 52 4e 41 4d 45 2e 7a 69 70 } //1 USERNAME.zip
		$a_01_3 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 35 36 35 31 32 34 33 37 30 31 } //1 api.telegram.org/bot5651243701
		$a_01_4 = {67 61 72 72 65 74 74 64 65 74 65 63 74 6f 72 73 2e 73 6b } //1 garrettdetectors.sk
		$a_01_5 = {41 50 50 44 41 54 41 5c 6f 74 2e 65 78 65 } //1 APPDATA\ot.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}