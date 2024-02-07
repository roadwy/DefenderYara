
rule Trojan_Win32_BHO_CF{
	meta:
		description = "Trojan:Win32/BHO.CF,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 68 74 74 70 3a 2f 2f 25 73 25 73 20 48 54 54 50 2f 31 2e 31 } //01 00  GET http://%s%s HTTP/1.1
		$a_01_1 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 7a 68 2d 63 6e } //01 00  Accept-Language:zh-cn
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 25 73 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\%s
		$a_01_3 = {2f 53 74 61 72 74 2e 68 74 6d 3f 41 72 65 61 49 44 3d 4e 61 4e 26 4d 65 64 69 61 49 44 3d 35 30 30 31 31 26 41 64 4e 6f 3d 25 64 26 4f 72 69 67 69 6e 61 6c 69 74 79 49 44 3d 25 64 26 55 72 6c 3d 42 48 4f 5f 53 74 61 72 74 5f 25 64 26 4d 61 63 3d 25 73 26 56 65 72 73 69 6f 6e 3d 25 64 26 56 61 6c 69 64 61 74 65 43 6f 64 65 3d 26 50 61 72 65 6e 74 4e 61 6d 65 3d 25 73 } //00 00  /Start.htm?AreaID=NaN&MediaID=50011&AdNo=%d&OriginalityID=%d&Url=BHO_Start_%d&Mac=%s&Version=%d&ValidateCode=&ParentName=%s
	condition:
		any of ($a_*)
 
}