
rule Backdoor_Win32_Adialer{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {64 69 61 6c 65 72 2d 70 6c 2d 74 65 6d 70 5c 64 69 61 6c 2d 69 6e 74 65 6c 6c 69 2d 76 90 02 05 5c 6b 6f 6c 2e 70 61 73 90 00 } //01 00 
		$a_02_1 = {49 6e 74 65 72 6e 65 74 20 53 65 78 70 6c 6f 72 65 72 20 90 02 05 20 50 4c 90 00 } //01 00 
		$a_00_2 = {53 20 45 20 58 20 50 20 4c 20 4f 20 52 20 45 20 52 } //01 00  S E X P L O R E R
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\Currentversion\Run
		$a_00_4 = {2f 6d 69 6e 20 7a 20 76 61 74 2e 20 4e 61 7a 77 61 20 6f 70 65 72 61 74 6f 72 61 20 70 6f 64 61 6e 61 20 6a 65 73 74 20 70 6f 6e 69 } //00 00  /min z vat. Nazwa operatora podana jest poni
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Adialer_2{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6c 4b 61 33 47 59 54 33 6a 79 64 4e 68 58 77 69 78 79 78 69 34 58 64 69 38 42 6d 30 47 4e 6c 36 71 59 43 69 62 72 4c 50 35 4f 51 58 59 38 46 41 4a 53 69 65 2f 76 69 4e 74 4a 6d 6b 77 31 30 51 71 31 77 4e 4d 73 74 2f 45 79 46 65 4b 6b 61 55 68 4b 65 5a 71 67 4f 64 4c 74 4a 55 61 45 6d 75 62 71 6b 79 68 57 52 42 } //02 00  lKa3GYT3jydNhXwixyxi4Xdi8Bm0GNl6qYCibrLP5OQXY8FAJSie/viNtJmkw10Qq1wNMst/EyFeKkaUhKeZqgOdLtJUaEmubqkyhWRB
		$a_01_1 = {6c 4c 79 74 75 6a 61 6b 47 4e 57 35 38 50 61 43 4a 35 68 63 2b 64 2f 59 72 68 63 54 56 52 47 70 65 32 67 78 49 44 75 59 4a 6b 50 52 49 55 63 4f 68 47 43 43 53 42 45 67 6d 4b 4f 6f 6a 73 78 42 39 6c 44 70 43 31 6b 63 76 31 49 63 38 41 3d 3d } //02 00  lLytujakGNW58PaCJ5hc+d/YrhcTVRGpe2gxIDuYJkPRIUcOhGCCSBEgmKOojsxB9lDpC1kcv1Ic8A==
		$a_01_2 = {6c 4a 79 67 70 72 75 44 4c 6a 35 37 6c 76 7a 48 35 44 55 35 56 37 32 32 71 79 2b 4b 6f 65 35 51 6a 36 63 59 69 66 59 6f 6c 6a 54 46 77 77 3d 3d } //00 00  lJygpruDLj57lvzH5DU5V722qy+Koe5Qj6cYifYoljTFww==
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Adialer_3{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_02_0 = {26 73 69 74 65 3d 90 02 08 26 63 6f 75 6e 74 72 79 3d 90 02 08 3f 77 65 62 6d 61 73 74 65 72 3d 90 00 } //01 00 
		$a_00_1 = {44 69 61 6c 20 65 72 72 6f 72 21 20 43 6f 64 65 3a 20 25 64 21 } //01 00  Dial error! Code: %d!
		$a_00_2 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 4c 6f 6f 70 } //01 00  if exist "%s" goto Loop
		$a_00_3 = {55 6e 69 6e 73 74 61 6c 6c 44 69 61 6c 65 72 2e 2e 2e } //01 00  UninstallDialer...
		$a_00_4 = {25 30 32 64 2e 25 30 32 64 2e 25 30 34 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 } //01 00  %02d.%02d.%04d %02d:%02d:%02d
		$a_00_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 43 6f 64 65 72 5c 63 6f 64 65 72 2e 6c 6f 67 } //01 00  C:\WINDOWS\Coder\coder.log
		$a_02_6 = {52 65 73 74 61 72 74 2e 2e 2e 90 02 05 48 61 6e 67 55 70 2e 2e 2e 90 00 } //01 00 
		$a_02_7 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 43 6f 64 65 72 5c 5f 90 01 01 2d 90 02 05 2d 90 01 01 2d 90 01 01 2d 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Adialer_4{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {81 bc 24 b0 02 00 00 39 1b 00 00 0f 85 c0 01 00 00 a1 90 01 02 40 00 85 c0 75 1f 8b 84 24 a8 02 00 00 68 39 1b 00 00 50 ff 15 90 01 02 40 00 90 00 } //02 00 
		$a_03_1 = {52 c7 84 24 fc 06 00 00 1c 04 00 00 ff d6 8d 84 24 fb 08 00 00 68 90 01 02 40 00 50 88 9c 24 01 08 00 00 88 9c 24 82 08 00 00 ff d6 8d 8c 24 fc 09 00 00 68 90 01 02 40 00 51 ff d6 8b 54 24 0c 53 53 8d 44 24 14 52 50 68 90 01 02 40 00 53 88 9c 24 15 0b 00 00 e8 90 01 02 00 00 90 00 } //01 00 
		$a_00_2 = {77 77 77 2e 74 6f 70 36 39 2e 6f 72 67 } //01 00  www.top69.org
		$a_00_3 = {52 61 73 44 69 61 6c 41 } //01 00  RasDialA
		$a_02_4 = {4e 65 74 73 63 61 70 65 2e 65 78 65 90 02 10 49 45 78 70 6c 6f 72 65 2e 65 78 65 90 02 10 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Adialer_5{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 64 65 6c 73 69 6d 00 00 75 6e 69 6e 73 74 53 68 6f 72 74 63 75 74 00 00 75 6e 69 6e 73 74 45 78 65 00 00 00 5c 00 00 00 55 6e 69 6e 73 74 61 6c 6c 53 74 72 69 6e 67 } //02 00 
		$a_01_1 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 44 65 6c 73 69 6d 20 44 69 61 6c 65 72 00 00 00 49 6e 74 65 72 6e 65 74 20 44 69 61 6c 65 72 } //02 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 72 61 66 66 69 63 6a 61 6d 2e 6e 6c 2f 3f 66 61 69 6c 65 64 3d 69 6e 69 74 69 61 6c 69 7a 65 2e 64 65 6c 73 69 6d 00 00 50 72 6f 67 72 61 6d 46 69 6c 65 73 44 69 72 00 } //02 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 70 72 73 2e 70 61 79 70 65 72 64 6f 77 6e 6c 6f 61 64 2e 6e 6c 2f 72 61 64 69 75 73 2f 64 69 61 6c 65 72 5f 61 64 6d 69 6e 2f 67 65 6f 69 70 2e 61 73 70 } //02 00  http://prs.payperdownload.nl/radius/dialer_admin/geoip.asp
		$a_01_4 = {44 3a 5c 57 6f 72 6b 5c 53 70 6c 65 6e 64 6f 5c 44 69 61 6c 65 72 5c 77 6f 72 6b 69 6e 67 5c 64 69 61 6c 65 72 20 68 69 64 64 65 6e 5f 69 70 32 63 6f 64 65 5f 63 6f 64 65 32 6e 72 73 5f 75 6e 69 6e 73 74 5c 49 6e 74 65 72 6e 65 74 44 69 61 6c 65 72 5c 43 2b 2b 20 53 6f 75 72 63 65 73 5c 44 69 61 6c 65 72 5c 42 73 64 4d 61 69 6e 44 6c 67 2e 63 70 70 } //02 00  D:\Work\Splendo\Dialer\working\dialer hidden_ip2code_code2nrs_uninst\InternetDialer\C++ Sources\Dialer\BsdMainDlg.cpp
		$a_00_5 = {44 00 65 00 6c 00 73 00 69 00 6d 00 20 00 44 00 69 00 61 00 6c 00 65 00 72 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 } //00 00  Delsim Dialer Module
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Adialer_6{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 f4 ff 75 08 e8 90 01 02 00 00 89 45 fc 03 45 08 89 45 f8 80 3d 90 01 02 40 00 31 74 24 c6 45 f7 7d eb 18 ff 4d fc ff 4d f8 8b 5d f8 b8 00 00 00 00 8a 03 2a 45 f7 88 03 88 45 f7 83 7d fc 00 75 e2 c9 c2 04 00 55 8b ec 68 90 00 } //02 00 
		$a_01_1 = {54 41 50 49 33 32 2e 44 4c 4c } //02 00  TAPI32.DLL
		$a_01_2 = {6c 69 6e 65 47 65 74 44 65 76 43 61 70 73 41 } //00 00  lineGetDevCapsA
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Adialer_7{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 30 38 38 31 39 33 39 31 31 30 } //02 00  00881939110
		$a_01_1 = {53 74 61 72 74 44 69 73 70 61 74 63 68 45 58 45 50 72 6f 63 65 73 73 } //02 00  StartDispatchEXEProcess
		$a_01_2 = {25 73 20 50 49 44 3a 25 64 20 45 58 45 3a 22 25 73 22 } //01 00  %s PID:%d EXE:"%s"
		$a_01_3 = {49 53 44 4e 00 00 00 00 4d 4f 44 45 4d } //04 00 
		$a_01_4 = {43 68 65 63 6b 20 25 69 00 00 00 00 6f 70 65 6e 00 00 00 00 25 69 } //06 00 
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 43 61 73 69 6f 70 00 } //00 00  体呆䅗䕒䍜獡潩p
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Adialer_8{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {3e 4c 69 6e 6b 20 55 6e 69 6e 73 74 61 6c 6c 3c 2f 61 3e } //02 00  >Link Uninstall</a>
		$a_01_1 = {5c 64 69 73 69 6e 73 74 61 6c 6c 61 2e 68 74 6d } //02 00  \disinstalla.htm
		$a_01_2 = {41 44 56 50 4c 55 47 49 4e 7c 4b } //01 00  ADVPLUGIN|K
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 55 73 65 72 20 41 67 65 6e 74 5c 50 6f 73 74 20 50 6c 61 74 66 6f 72 6d } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\User Agent\Post Platform
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Adialer_9{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 30 38 38 31 39 33 39 31 31 30 } //01 00  00881939110
		$a_01_1 = {73 73 61 76 65 72 73 } //01 00  ssavers
		$a_01_2 = {73 74 61 74 69 63 75 73 65 72 6e 61 6d 65 3a } //01 00  staticusername:
		$a_01_3 = {76 78 64 35 } //01 00  vxd5
		$a_01_4 = {76 78 64 34 } //01 00  vxd4
		$a_01_5 = {76 78 64 33 } //01 00  vxd3
		$a_01_6 = {76 78 64 32 } //01 00  vxd2
		$a_01_7 = {49 53 44 4e 00 00 00 00 4d 4f 44 45 4d } //04 00 
		$a_01_8 = {64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 00 00 00 00 25 73 25 69 2e 62 61 74 } //04 00 
		$a_01_9 = {43 68 65 63 6b 20 25 69 00 00 00 00 6f 70 65 6e 00 00 00 00 25 69 } //08 00 
		$a_01_10 = {53 4f 46 54 57 41 52 45 5c 43 61 73 69 6f 70 00 6d 6f 64 65 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Adialer_10{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 4d 00 00 03 00 "
		
	strings :
		$a_01_0 = {47 65 6e 75 69 6e 65 49 70 } //01 00  GenuineIp
		$a_01_1 = {52 61 73 47 65 74 45 6e 74 72 79 50 72 6f 70 65 72 74 69 65 73 41 } //01 00  RasGetEntryPropertiesA
		$a_01_2 = {52 61 73 44 69 61 6c 41 } //01 00  RasDialA
		$a_01_3 = {74 72 69 6e 69 64 61 64 20 26 20 74 6f 62 61 67 6f } //01 00  trinidad & tobago
		$a_01_4 = {73 70 61 6e 69 73 68 2d 65 6c 20 73 61 6c 76 61 64 6f 72 } //01 00  spanish-el salvador
		$a_01_5 = {73 70 61 6e 69 73 68 2d 61 72 67 65 6e 74 69 6e 61 } //01 00  spanish-argentina
		$a_01_6 = {70 6f 72 74 75 67 75 65 73 65 2d 62 72 61 7a 69 6c 69 61 6e } //01 00  portuguese-brazilian
		$a_01_7 = {6e 6f 72 77 65 67 69 61 6e 2d 6e 79 6e 6f 72 73 6b } //01 00  norwegian-nynorsk
		$a_01_8 = {6e 6f 72 77 65 67 69 61 6e 2d 62 6f 6b 6d 61 6c } //01 00  norwegian-bokmal
		$a_01_9 = {65 6e 67 6c 69 73 68 2d 74 72 69 6e 69 64 61 64 20 79 20 74 6f 62 61 67 6f } //02 00  english-trinidad y tobago
		$a_01_10 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 73 } //02 00  Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones
		$a_01_11 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 79 73 74 65 6d 43 65 72 74 69 66 69 63 61 74 65 73 5c 54 72 75 73 74 65 64 50 75 62 6c 69 73 68 65 72 5c 43 65 72 74 69 66 69 63 61 74 65 73 } //02 00  Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates
		$a_01_12 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 54 72 75 73 74 5c 54 72 75 73 74 20 50 72 6f 76 69 64 65 72 73 5c 53 6f 66 74 77 61 72 65 20 50 75 62 6c 69 73 68 69 6e 67 5c 54 72 75 73 74 20 44 61 74 61 62 61 73 65 5c 30 } //02 00  Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\Trust Database\0
		$a_01_13 = {50 72 6f 78 79 45 6e 61 62 6c 65 } //04 00  ProxyEnable
		$a_01_14 = {63 6d 64 6c 69 6e 65 3a 20 25 73 2c 20 5f 53 68 6f 77 41 67 72 3d 25 64 2c 20 5f 41 75 74 6f 73 74 3d 25 64 } //04 00  cmdline: %s, _ShowAgr=%d, _Autost=%d
		$a_01_15 = {44 65 6e 74 72 6f 20 52 61 73 44 69 61 6c 46 75 6e 63 20 63 6f 6e 20 52 41 53 43 4f 4e 4e 53 54 41 54 45 3d 25 64 } //09 00  Dentro RasDialFunc con RASCONNSTATE=%d
		$a_01_16 = {72 74 61 59 44 6a 77 4c 67 23 66 43 53 34 45 39 6e 71 56 6b 68 73 63 4f 48 62 76 6d 33 52 4a 35 36 78 70 54 5a 49 37 6c 58 69 2b 57 47 6f 32 4d 75 38 4b 51 42 31 64 50 55 41 4e 7a 65 30 46 79 } //02 00  rtaYDjwLg#fCS4E9nqVkhscOHbvm3RJ56xpTZI7lXi+WGo2Mu8KQB1dPUANze0Fy
		$a_01_17 = {4d 69 20 73 74 6f 20 64 69 73 63 6f 6e 6e 65 74 74 65 6e 64 6f 2e 2e 2e } //04 00  Mi sto disconnettendo...
		$a_01_18 = {34 20 4d 61 6e 61 67 65 44 69 61 6c 69 6e 67 20 66 72 6f 6d 6d 65 6e 75 3d 25 64 2c 73 6b 69 70 41 67 72 65 65 6d 65 6e 74 3d 25 64 } //04 00  4 ManageDialing frommenu=%d,skipAgreement=%d
		$a_01_19 = {45 72 72 6f 72 65 20 6e 65 6c 6c 61 20 63 6f 6e 6e 65 73 73 69 6f 6e 65 3a 72 65 74 76 61 6c 75 65 3d 20 25 64 20 28 25 78 29 2c 20 47 4c 45 3a 25 64 20 28 25 78 29 } //04 00  Errore nella connessione:retvalue= %d (%x), GLE:%d (%x)
		$a_01_20 = {25 73 20 25 64 20 28 25 78 20 2d 20 25 73 29 2c 20 47 4c 45 3a 25 64 20 28 25 78 29 } //04 00  %s %d (%x - %s), GLE:%d (%x)
		$a_01_21 = {25 73 20 25 73 20 25 64 20 25 73 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 5b 54 25 64 54 5d 2e 75 72 6c } //04 00  %s %s %d %s                 [T%dT].url
		$a_01_22 = {49 6d 70 6f 73 73 69 62 69 6c 65 20 63 72 65 61 72 65 20 6c 61 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 20 45 72 72 6f 72 20 25 6c 64 } //04 00  Impossibile creare la connection information  Error %ld
		$a_01_23 = {4e 6f 6e 20 72 69 65 73 63 6f 20 61 20 63 72 65 61 72 65 20 6c 61 20 70 68 6f 6e 65 62 6f 6f 6b 20 65 6e 74 72 79 2e 20 28 6d 6f 64 65 6d 3a 25 73 29 20 45 72 72 6f 72 65 20 25 6c 64 } //03 00  Non riesco a creare la phonebook entry. (modem:%s) Errore %ld
		$a_01_24 = {52 44 46 2d 6d 73 67 3d 25 64 20 72 63 73 3d 25 64 2c 20 64 77 45 72 72 3d 25 64 } //03 00  RDF-msg=%d rcs=%d, dwErr=%d
		$a_01_25 = {25 73 20 2f 61 73 74 61 72 74 } //01 00  %s /astart
		$a_01_26 = {49 6d 70 6f 73 73 69 62 69 6c 65 20 63 6f 6e 6e 65 74 74 65 72 73 69 2e 20 41 73 73 65 6e 7a 61 20 64 69 20 6c 69 6e 65 61 2e 20 43 6f 6e 74 72 6f 6c 6c 61 72 65 20 63 68 65 20 69 6c 20 6d 6f 64 65 6d 20 73 69 61 20 61 63 63 65 73 6f 20 65 20 63 6f 6e 6e 65 73 73 6f 2e } //01 00  Impossibile connettersi. Assenza di linea. Controllare che il modem sia acceso e connesso.
		$a_01_27 = {4e 65 73 73 75 6e 20 4d 6f 64 65 6d 20 52 69 6c 65 76 61 74 6f 2e 20 43 6f 6e 74 72 6f 6c 6c 61 72 65 20 65 20 72 69 70 72 6f 76 61 72 65 2e } //01 00  Nessun Modem Rilevato. Controllare e riprovare.
		$a_01_28 = {4e 65 73 73 75 6e 20 44 69 73 70 6f 73 69 74 69 76 6f 20 52 69 6c 65 76 61 74 6f 20 6f 20 45 72 72 6f 72 65 2e 20 43 6f 6e 74 72 6f 6c 6c 61 72 65 20 65 20 72 69 70 72 6f 76 61 72 65 2e } //03 00  Nessun Dispositivo Rilevato o Errore. Controllare e riprovare.
		$a_01_29 = {45 72 72 6f 72 65 20 6e 65 6c 20 72 69 6c 61 73 63 69 6f 20 64 65 6c 20 63 65 72 74 69 66 69 63 61 74 6f 20 64 69 20 61 74 74 69 76 61 7a 69 6f 6e 65 2e 20 54 72 61 6e 73 61 7a 69 6f 6e 65 20 61 62 6f 72 74 69 74 61 2e 20 4e 65 73 73 75 6e 20 61 64 64 65 62 69 74 6f 20 76 65 72 72 61 27 20 65 66 66 65 74 74 75 61 74 6f 2e } //01 00  Errore nel rilascio del certificato di attivazione. Transazione abortita. Nessun addebito verra' effettuato.
		$a_01_30 = {43 6f 6e 6e 65 73 73 6f } //01 00  Connesso
		$a_01_31 = {56 75 6f 69 20 72 69 63 6f 6e 6e 65 74 74 65 72 74 69 3f } //01 00  Vuoi riconnetterti?
		$a_01_32 = {52 69 63 6f 6e 6e 65 73 73 69 6f 6e 65 } //01 00  Riconnessione
		$a_01_33 = {44 69 73 63 6f 6e 6e 65 73 73 6f } //03 00  Disconnesso
		$a_01_34 = {54 49 53 43 41 4c 49 } //03 00  TISCALI
		$a_01_35 = {4c 49 42 45 52 4f } //03 00  LIBERO
		$a_01_36 = {56 49 52 47 49 4c 49 4f } //03 00  VIRGILIO
		$a_01_37 = {43 4c 41 52 45 4e 43 45 } //03 00  CLARENCE
		$a_01_38 = {4b 41 54 41 57 45 42 } //03 00  KATAWEB
		$a_01_39 = {4a 55 4d 50 59 } //03 00  JUMPY
		$a_01_40 = {56 69 72 67 69 6c 69 6f 47 6f 6f 67 6c 65 } //05 00  VirgilioGoogle
		$a_01_41 = {4c 47 73 6f 6e 79 2d 6a 52 46 43 31 35 37 59 52 46 43 34 39 33 7a } //06 00  LGsony-jRFC157YRFC493z
		$a_01_42 = {4f 76 65 72 74 75 72 65 57 77 49 69 4e 6e 44 64 4f 6f 57 77 53 73 32 4b 6b 2f 72 66 63 37 36 35 77 49 4e 44 6f 77 73 32 6b 52 46 43 34 39 33 31 } //02 00  OvertureWwIiNnDdOoWwSs2Kk/rfc765wINDows2kRFC4931
		$a_01_43 = {25 73 5c 41 44 44 49 4e 53 } //01 00  %s\ADDINS
		$a_01_44 = {2f 6e 6f 69 6e 73 74 61 6c 6c } //02 00  /noinstall
		$a_01_45 = {25 73 5f 43 6f 6e 6e 65 63 74 69 6f 6e } //06 00  %s_Connection
		$a_01_46 = {41 72 65 61 20 61 64 75 6c 74 69 } //14 00  Area adulti
		$a_01_47 = {77 77 77 2e 74 6f 70 36 39 2e 6f 72 67 2f 69 6e 64 65 78 2e 70 68 70 } //14 00  www.top69.org/index.php
		$a_01_48 = {77 77 77 2e 77 65 62 63 6f 6e 74 2e 6e 65 74 2f 43 4f 4e 54 45 4e 54 53 } //03 00  www.webcont.net/CONTENTS
		$a_01_49 = {54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 75 73 69 6e 67 20 74 68 69 73 20 44 69 61 6c 65 72 2e } //05 00  Thank you for using this Dialer.
		$a_01_50 = {6d 69 63 69 6f 5f 62 61 75 } //0a 00  micio_bau
		$a_01_51 = {73 70 61 72 65 73 2f 63 6f 64 65 2f 67 65 74 2e 70 68 70 } //0a 00  spares/code/get.php
		$a_01_52 = {47 45 54 20 2f 25 73 3f 69 64 64 6c 3d 25 64 26 63 6c 69 64 3d 25 64 26 61 76 72 31 3d 25 64 26 61 76 72 32 3d 25 64 26 61 76 72 33 3d 25 64 20 48 54 54 50 2f 31 2e 30 20 } //06 00  GET /%s?iddl=%d&clid=%d&avr1=%d&avr2=%d&avr3=%d HTTP/1.0 
		$a_01_53 = {4e 54 53 2f 61 64 75 6c 74 63 6f 6e 74 2f 69 6e 64 65 78 2e 70 68 70 } //14 00  NTS/adultcont/index.php
		$a_01_54 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 75 62 69 6c 65 6f 6e 65 73 2e 63 6f 6d 2f 6d 65 6d 62 65 72 73 2f } //14 00  http://www.nubileones.com/members/
		$a_01_55 = {42 4f 4f 54 2d 46 33 37 44 32 38 43 45 2d 43 45 33 37 2d 34 62 63 38 2d 42 31 32 38 2d 45 41 32 37 37 34 37 42 45 35 45 37 } //05 00  BOOT-F37D28CE-CE37-4bc8-B128-EA27747BE5E7
		$a_01_56 = {65 72 72 3d 65 78 69 74 20 66 72 6f 6d 20 74 72 79 62 61 72 } //05 00  err=exit from trybar
		$a_01_57 = {43 6f 6e 6e 65 63 74 65 64 3a 20 25 30 32 69 3a 25 30 32 69 3a 25 30 32 69 } //02 00  Connected: %02i:%02i:%02i
		$a_01_58 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 41 63 74 69 76 65 58 20 43 61 63 68 65 } //04 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ActiveX Cache
		$a_01_59 = {73 74 61 6e 64 61 6c 6f 6e 65 3d 22 25 73 22 20 } //0a 00  standalone="%s" 
		$a_01_60 = {7b 37 35 32 31 49 54 31 31 2d 31 31 31 31 2d 31 31 31 31 2d 31 31 31 31 2d 31 31 31 31 31 31 31 31 31 31 31 31 7d } //02 00  {7521IT11-1111-1111-1111-111111111111}
		$a_01_61 = {22 25 73 22 20 50 49 44 3a 25 64 20 45 58 45 3a 22 25 73 22 } //04 00  "%s" PID:%d EXE:"%s"
		$a_01_62 = {54 68 65 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 68 61 73 20 62 65 65 6e 20 63 6c 6f 73 65 64 20 28 65 78 74 65 72 6e 61 6c 6c 79 29 2e 2e 2e } //04 00  The connection has been closed (externally)...
		$a_01_63 = {5f 66 6f 6f 62 61 72 5f 2e 65 78 65 } //04 00  _foobar_.exe
		$a_01_64 = {64 69 73 63 6c 61 69 6d 65 72 5f 64 73 } //04 00  disclaimer_ds
		$a_01_65 = {64 69 61 6c 5f 67 65 6e 65 72 61 74 69 6f 6e } //03 00  dial_generation
		$a_01_66 = {52 65 67 69 73 74 65 72 69 6e 67 20 63 6f 6d 70 75 74 65 72 20 6f 6e 20 74 68 65 20 6e 65 74 77 6f 72 6b 2e 2e 2e } //03 00  Registering computer on the network...
		$a_01_67 = {4c 6f 67 67 69 6e 67 20 6f 6e 20 74 6f 20 74 68 65 20 6e 65 74 77 6f 72 6b 2e 2e 2e } //03 00  Logging on to the network...
		$a_01_68 = {48 61 69 20 73 63 65 6c 74 6f 20 64 69 20 6e 6f 6e 20 61 74 74 69 76 61 72 65 20 75 6e 20 6e 75 6f 76 6f 20 61 62 62 6f 6e 61 6d 65 6e 74 6f 2e } //02 00  Hai scelto di non attivare un nuovo abbonamento.
		$a_01_69 = {42 41 4b 7c 25 73 7c 25 30 34 64 7c 25 64 7c 25 63 7c 25 73 7c 45 41 4b } //03 00  BAK|%s|%04d|%d|%c|%s|EAK
		$a_01_70 = {70 72 65 63 65 64 65 6e 74 65 6d 65 6e 74 65 20 61 63 63 65 74 74 61 74 65 2e } //03 00  precedentemente accettate.
		$a_01_71 = {4e 2e 42 2e 3a 20 69 20 74 69 63 6b 65 74 20 61 63 71 75 69 73 74 61 74 69 20 63 6f 6e 20 71 75 65 73 74 6f 20 70 72 6f 67 72 61 6d 6d 61 20 73 61 72 61 6e 6e 6f 20 76 61 6c 69 64 69 20 66 69 6e 6f 20 61 6c } //14 00  N.B.: i ticket acquistati con questo programma saranno validi fino al
		$a_01_72 = {54 69 6e 79 44 69 61 6c 65 72 2b } //05 00  TinyDialer+
		$a_01_73 = {75 70 64 2e 65 78 65 } //01 00  upd.exe
		$a_01_74 = {55 6e 4e 65 74 } //01 00  UnNet
		$a_01_75 = {67 65 66 65 72 71 } //03 00  geferq
		$a_01_76 = {43 3a 5c 75 6e 2e 65 78 65 } //00 00  C:\un.exe
	condition:
		any of ($a_*)
 
}