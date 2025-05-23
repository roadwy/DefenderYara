
rule TrojanSpy_Win32_Bancos_OQ{
	meta:
		description = "TrojanSpy:Win32/Bancos.OQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f ?? ?? ?? 2e 6c 32 63 72 61 7a 79 70 76 70 2e 63 6f 6d 2f [0-07] 2e 70 61 63 } //1
		$a_00_1 = {75 00 73 00 65 00 72 00 5f 00 70 00 72 00 65 00 66 00 28 00 22 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 2e 00 70 00 72 00 6f 00 78 00 79 00 2e 00 61 00 75 00 74 00 6f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5f 00 75 00 72 00 6c 00 22 00 2c 00 20 00 22 00 } //1 user_pref("network.proxy.autoconfig_url", "
		$a_00_2 = {63 68 61 76 65 69 65 3d 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //1 chaveie=\Software\Microsoft\Windows\CurrentVersion\Internet Settings
		$a_80_3 = {68 74 74 70 3a 2f 2f 64 69 61 6d 6f 6e 64 2e 69 6e 6f 76 61 6c 69 6e 6b 2e 6e 65 74 2f 77 61 62 2f 69 6e 64 65 78 32 2e 70 68 70 } //http://diamond.inovalink.net/wab/index2.php  1
		$a_00_4 = {2e 65 78 65 20 28 6e 75 6c 6c 29 20 74 72 75 65 20 66 61 6c 73 65 20 74 72 75 65 20 74 72 75 65 20 28 6e 75 6c 6c 29 20 28 6e 75 6c 6c 29 20 22 68 74 74 70 3a 2f 2f } //1 .exe (null) true false true true (null) (null) "http://
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
rule TrojanSpy_Win32_Bancos_OQ_2{
	meta:
		description = "TrojanSpy:Win32/Bancos.OQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_02_0 = {65 00 63 00 68 00 6f 00 20 00 75 00 73 00 65 00 72 00 5f 00 70 00 72 00 65 00 66 00 28 00 22 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 2e 00 70 00 72 00 6f 00 78 00 79 00 2e 00 61 00 75 00 74 00 6f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5f 00 75 00 72 00 6c 00 22 00 2c 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-60] 2e 00 70 00 61 00 63 00 22 00 29 00 3b 00 20 00 3e 00 3e 00 70 00 72 00 65 00 66 00 73 00 2e 00 6a 00 73 00 } //1
		$a_00_1 = {65 00 63 00 68 00 6f 00 20 00 75 00 73 00 65 00 72 00 5f 00 70 00 72 00 65 00 66 00 28 00 22 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 2e 00 70 00 72 00 6f 00 78 00 79 00 2e 00 74 00 79 00 70 00 65 00 22 00 2c 00 20 00 32 00 29 00 3b 00 20 00 3e 00 3e 00 70 00 72 00 65 00 66 00 73 00 2e 00 6a 00 73 00 } //1 echo user_pref("network.proxy.type", 2); >>prefs.js
		$a_00_2 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 73 00 3a 00 7b 00 69 00 6d 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 4c 00 65 00 76 00 65 00 6c 00 3d 00 69 00 6d 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 74 00 65 00 7d 00 21 00 5c 00 5c 00 2e 00 5c 00 72 00 6f 00 6f 00 74 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 } //1 winmgmts:{impersonationLevel=impersonate}!\\.\root\SecurityCenter
		$a_00_3 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 Select * from AntiVirusProduct
		$a_02_4 = {3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 [0-20] 5b 00 78 00 78 00 5d 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 3a 00 [0-30] 43 00 3a 00 5c 00 } //1
		$a_01_5 = {52 00 65 00 63 00 65 00 62 00 65 00 75 00 5b 00 2d 00 5d 00 20 00 5b 00 20 00 4a 00 6f 00 72 00 6e 00 61 00 6c 00 3a 00 20 00 5d 00 } //1 Recebeu[-] [ Jornal: ]
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule TrojanSpy_Win32_Bancos_OQ_3{
	meta:
		description = "TrojanSpy:Win32/Bancos.OQ,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 6e 00 61 00 74 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 28 00 6e 00 75 00 6c 00 6c 00 29 00 20 00 74 00 72 00 75 00 65 00 20 00 66 00 61 00 6c 00 73 00 65 00 20 00 74 00 72 00 75 00 65 00 20 00 74 00 72 00 75 00 65 00 20 00 28 00 6e 00 75 00 6c 00 6c 00 29 00 20 00 28 00 6e 00 75 00 6c 00 6c 00 29 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6e 00 62 00 62 00 2e 00 6c 00 32 00 63 00 72 00 61 00 7a 00 79 00 70 00 76 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 2e 00 70 00 61 00 63 00 } //1 \nat32.exe (null) true false true true (null) (null) http://nbb.l2crazypvp.com/network.pac
		$a_01_1 = {43 00 3a 00 5c 00 42 00 75 00 69 00 6c 00 64 00 73 00 5c 00 54 00 50 00 5c 00 69 00 6e 00 64 00 79 00 73 00 6f 00 63 00 6b 00 65 00 74 00 73 00 5c 00 6c 00 69 00 62 00 5c 00 50 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 73 00 5c 00 49 00 64 00 53 00 53 00 4c 00 4f 00 70 00 65 00 6e 00 53 00 53 00 4c 00 2e 00 70 00 61 00 73 00 } //1 C:\Builds\TP\indysockets\lib\Protocols\IdSSLOpenSSL.pas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}