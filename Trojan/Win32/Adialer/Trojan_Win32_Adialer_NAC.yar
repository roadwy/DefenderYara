
rule Trojan_Win32_Adialer_NAC{
	meta:
		description = "Trojan:Win32/Adialer.NAC,SIGNATURE_TYPE_PEHSTR_EXT,20 00 1b 00 0d 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 43 61 72 6c 73 6f 6e } //5 SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Carlson
		$a_00_1 = {43 61 72 6c 73 6f 6e 20 44 69 61 6c 65 72 } //5 Carlson Dialer
		$a_00_2 = {68 74 74 70 3a 2f 2f 70 72 73 2e 70 61 79 70 65 72 64 6f 77 6e 6c 6f 61 64 2e 6e 6c } //5 http://prs.payperdownload.nl
		$a_00_3 = {52 61 73 45 6e 75 6d 43 6f 6e 6e 65 63 74 69 6f 6e 73 41 } //5 RasEnumConnectionsA
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //5 InternetOpenUrlA
		$a_00_5 = {39 42 34 41 41 34 34 32 2d 39 45 42 46 2d 31 31 44 35 2d 38 43 31 31 2d 30 30 35 30 44 41 34 39 35 37 46 35 } //5 9B4AA442-9EBF-11D5-8C11-0050DA4957F5
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 Software\Microsoft\Internet Explorer\Main
		$a_00_7 = {26 6c 61 73 74 65 72 72 6f 72 3d } //1 &lasterror=
		$a_00_8 = {26 6c 69 6e 65 6e 75 6d 62 65 72 3d } //1 &linenumber=
		$a_00_9 = {72 65 61 6c 6e 75 6d 62 65 72 } //1 realnumber
		$a_00_10 = {63 61 6c 6c 72 65 63 6f 72 64 73 } //1 callrecords
		$a_00_11 = {68 74 74 70 3a 2f 2f 70 72 73 2e 70 61 79 70 65 72 64 6f 77 6e 6c 6f 61 64 2e 6e 6c 2f 72 61 64 69 75 73 2f 64 69 61 6c 65 72 5f 61 64 6d 69 6e 2f 67 65 6f 69 70 } //1 http://prs.payperdownload.nl/radius/dialer_admin/geoip
		$a_00_12 = {61 6e 67 65 6c 40 63 61 72 6c 74 6f 6e } //1 angel@carlton
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_01_4  & 1)*5+(#a_00_5  & 1)*5+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=27
 
}