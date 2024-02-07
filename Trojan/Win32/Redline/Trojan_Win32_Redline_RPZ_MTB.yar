
rule Trojan_Win32_Redline_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {f6 17 33 db 33 c3 33 d8 80 2f 80 8b f0 33 de 8b c6 80 07 34 33 d8 33 db 33 db f6 2f 47 e2 e1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {f7 ff 83 e0 4a 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb 8b 4d 0c 03 4d fc 0f b6 11 2b d0 8b 45 0c 03 45 fc 88 10 eb 83 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 80 90 01 04 32 04 37 88 45 d3 ba 90 00 } //01 00 
		$a_01_1 = {59 0f b6 1c 37 8a c3 02 45 d3 88 04 37 ba } //01 00 
		$a_01_2 = {59 28 1c 37 46 8b 45 c8 eb b1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_RPZ_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 ca 88 4d ff 8b 45 0c 03 45 f8 8a 08 88 4d fd 0f b6 55 ff 8b 45 0c 03 45 f8 0f b6 08 03 ca 8b 55 0c 03 55 f8 88 0a 8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 0c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_RPZ_MTB_5{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c4 89 44 24 2c 8b 41 3c 53 8b da 89 4c 24 0c 55 8b 54 08 78 33 ed 8b 44 0a 20 03 d1 89 54 24 18 03 c1 56 57 8b 52 18 89 5c 24 14 89 44 24 10 89 54 24 1c 85 d2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_RPZ_MTB_6{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 fc 50 6a 40 8b 4d 0c 51 8b 55 08 52 ff 15 90 01 03 00 33 c0 33 d2 8b e5 5d c3 90 00 } //01 00 
		$a_01_1 = {33 f0 03 ce 8b 55 0c 03 55 dc 88 0a 0f be 45 db 8b 4d 0c 03 4d dc 0f b6 11 2b d0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_RPZ_MTB_7{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 00 70 00 69 00 2e 00 69 00 70 00 2e 00 73 00 62 00 } //01 00  api.ip.sb
		$a_01_1 = {46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 72 00 65 00 63 00 65 00 6e 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c 00 } //01 00  FileZilla\recentservers.xml
		$a_01_2 = {52 00 75 00 73 00 73 00 69 00 61 00 } //01 00  Russia
		$a_01_3 = {64 00 69 00 73 00 63 00 6f 00 72 00 64 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 5c 00 6c 00 65 00 76 00 65 00 6c 00 64 00 62 00 } //01 00  discord\Local Storage\leveldb
		$a_01_4 = {75 00 73 00 65 00 72 00 2e 00 63 00 6f 00 6e 00 66 00 69 00 67 00 } //01 00  user.config
		$a_01_5 = {4f 00 70 00 65 00 72 00 61 00 20 00 47 00 58 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //01 00  Opera GXcookies
		$a_01_6 = {6d 00 6f 00 7a 00 5f 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //01 00  moz_cookies
		$a_01_7 = {4e 00 6f 00 72 00 64 00 56 00 70 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  NordVpn.exe
		$a_01_8 = {2a 00 77 00 61 00 6c 00 6c 00 65 00 74 00 2a 00 } //01 00  *wallet*
		$a_01_9 = {73 00 74 00 72 00 69 00 6e 00 67 00 2e 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 } //01 00  string.Replace
		$a_01_10 = {46 00 69 00 6c 00 65 00 2e 00 57 00 72 00 69 00 74 00 65 00 } //01 00  File.Write
		$a_01_11 = {4d 00 6f 00 6c 00 64 00 6f 00 76 00 61 00 } //01 00  Moldova
		$a_01_12 = {41 00 72 00 6d 00 65 00 6e 00 69 00 61 00 } //01 00  Armenia
		$a_01_13 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //01 00  shell\open\command
		$a_01_14 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 43 00 6c 00 69 00 65 00 6e 00 74 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 4d 00 65 00 6e 00 75 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 } //01 00  SOFTWARE\Clients\StartMenuInternet
		$a_01_15 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_01_16 = {47 65 74 42 72 6f 77 73 65 72 73 } //01 00  GetBrowsers
		$a_01_17 = {69 6e 73 74 61 6c 6c 65 64 42 72 6f 77 73 65 72 73 } //00 00  installedBrowsers
	condition:
		any of ($a_*)
 
}