
rule Trojan_BAT_RealProtect_CM_MTB{
	meta:
		description = "Trojan:BAT/RealProtect.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 48 52 30 63 44 6f 76 4c 32 6c 77 61 57 35 6d 62 79 35 70 62 77 3d 3d } //01 00  aHR0cDovL2lwaW5mby5pbw==
		$a_81_1 = {64 58 4e 6c 63 69 31 68 5a 32 56 75 64 41 3d 3d } //01 00  dXNlci1hZ2VudA==
		$a_81_2 = {54 57 39 36 61 57 78 73 59 53 38 30 4c 6a 41 67 4b 47 4e 76 62 58 42 68 64 47 6c 69 62 47 55 37 49 45 31 54 53 55 55 67 4e 69 34 77 4f 79 42 58 61 57 35 6b 62 33 64 7a 49 45 35 55 49 44 55 75 4d 6a 73 67 4c 6b 35 46 56 43 42 44 54 46 49 67 4d 53 34 77 4c 6a 4d 33 4d 44 55 37 4b 51 3d 3d } //01 00  TW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNi4wOyBXaW5kb3dzIE5UIDUuMjsgLk5FVCBDTFIgMS4wLjM3MDU7KQ==
		$a_81_3 = {58 47 31 6c 65 6d 45 3d } //01 00  XG1lemE=
		$a_81_4 = {48 50 2e 65 78 65 } //01 00  HP.exe
		$a_81_5 = {31 32 37 2e 30 2e 30 2e 31 20 65 6c 73 6a 2e 62 61 6e 6f 72 74 65 2e 63 6f 6d } //01 00  127.0.0.1 elsj.banorte.com
		$a_81_6 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 43 3a } //01 00  powershell -Command Add-MpPreference -ExclusionPath C:
		$a_81_7 = {64 72 69 76 65 72 73 2f 65 74 63 2f 68 6f 73 74 73 } //00 00  drivers/etc/hosts
	condition:
		any of ($a_*)
 
}