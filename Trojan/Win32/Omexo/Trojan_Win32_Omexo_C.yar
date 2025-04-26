
rule Trojan_Win32_Omexo_C{
	meta:
		description = "Trojan:Win32/Omexo.C,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0e 00 14 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 43 6c 69 65 6e 74 73 5c 53 74 61 72 74 4d 65 6e 75 49 6e 74 65 72 6e 65 74 5c 66 69 72 65 66 6f 78 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 SOFTWARE\Clients\StartMenuInternet\firefox.exe\shell\open\command
		$a_00_2 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 \\?\globalroot\systemroot\system32\drivers\etc\hosts
		$a_00_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 } //1 \\.\PhysicalDrive%d
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 79 70 65 64 55 52 4c 73 } //1 Software\Microsoft\Internet Explorer\TypedURLs
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 6e 74 65 6c 6c 69 46 6f 72 6d 73 5c 53 74 6f 72 61 67 65 32 } //1 Software\Microsoft\Internet Explorer\IntelliForms\Storage2
		$a_00_6 = {50 4b 31 31 5f 43 68 65 63 6b 55 73 65 72 50 61 73 73 77 6f 72 64 } //1 PK11_CheckUserPassword
		$a_00_7 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
		$a_00_8 = {63 6f 6f 6b 69 65 73 69 65 2e 7a } //1 cookiesie.z
		$a_00_9 = {63 6f 6f 6b 69 65 73 2e 7a } //1 cookies.z
		$a_00_10 = {6b 65 79 6c 6f 67 2e 7a } //1 keylog.z
		$a_00_11 = {63 65 72 74 73 2e 7a } //1 certs.z
		$a_00_12 = {73 79 73 69 6e 66 6f 2e 7a } //1 sysinfo.z
		$a_00_13 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 7c 6f 70 65 72 61 2e 65 78 65 7c 66 69 72 65 66 6f 78 2e 65 78 65 } //1 iexplore.exe|opera.exe|firefox.exe
		$a_00_14 = {73 72 63 3d 27 68 74 74 70 3a 2f 2f 25 73 2f 6a 62 69 6e 66 6f 2e 63 67 69 3f 25 73 3a 25 64 27 3e } //1 src='http://%s/jbinfo.cgi?%s:%d'>
		$a_00_15 = {47 6c 6f 62 61 6c 5c 7b 37 32 31 45 33 41 36 31 2d 38 38 33 42 2d 34 31 34 34 2d 42 41 38 31 2d 31 46 39 36 35 38 37 39 45 35 43 39 7d } //1 Global\{721E3A61-883B-4144-BA81-1F965879E5C9}
		$a_00_16 = {41 55 54 48 49 4e 46 4f 20 50 41 53 53 20 } //1 AUTHINFO PASS 
		$a_00_17 = {73 74 65 61 6c 69 74 } //1 stealit
		$a_00_18 = {70 61 73 73 5f 6c 6f 67 } //1 pass_log
		$a_00_19 = {73 6e 69 66 66 5f 6c 6f 67 } //1 sniff_log
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*1) >=14
 
}