
rule Trojan_Win32_Azorult_ibt{
	meta:
		description = "Trojan:Win32/Azorult!ibt,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c7 07 3c 00 00 00 8d 45 80 89 47 04 c7 47 08 20 00 00 00 8d 85 80 fe ff ff 89 47 10 c7 47 14 00 01 00 00 8d 85 00 fe ff ff 89 47 1c c7 47 20 80 00 00 00 8d 85 80 fd ff ff 89 47 24 c7 47 28 80 00 00 00 8d 85 80 f5 ff ff 89 47 2c c7 47 30 00 08 00 00 8d 85 80 f1 ff ff 89 47 34 c7 47 38 00 04 00 00 57 68 00 00 00 90 8b 45 cc } //0a 00 
		$a_01_1 = {53 45 4c 45 43 54 20 44 41 54 45 54 49 4d 45 28 20 28 28 76 69 73 69 74 73 2e 76 69 73 69 74 5f 74 69 6d 65 2f 31 30 30 30 30 30 30 29 2d 31 31 36 34 34 34 37 33 36 30 30 29 2c 22 75 6e 69 78 65 70 6f 63 68 22 29 } //00 00  SELECT DATETIME( ((visits.visit_time/1000000)-11644473600),"unixepoch")
	condition:
		any of ($a_*)
 
}