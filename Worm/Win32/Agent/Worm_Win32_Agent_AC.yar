
rule Worm_Win32_Agent_AC{
	meta:
		description = "Worm:Win32/Agent.AC,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 63 68 72 2f 39 30 37 2f 6e 74 2e 65 78 65 20 48 54 54 50 2f 31 2e 31 } //0a 00  GET /chr/907/nt.exe HTTP/1.1
		$a_01_1 = {48 6f 73 74 3a 20 77 77 77 36 2e 62 61 64 65 73 75 67 65 72 77 61 6b 69 72 70 6f 73 2e 63 6f 6d } //0a 00  Host: www6.badesugerwakirpos.com
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 36 2e 62 61 64 65 73 75 67 65 72 77 61 6b 69 72 70 6f 73 2e 63 6f 6d 2f 63 68 72 2f 39 30 37 2f 6e 74 2e 65 78 65 } //01 00  http://www6.badesugerwakirpos.com/chr/907/nt.exe
		$a_00_3 = {41 63 63 65 70 74 3a 20 2a 2f 2a } //01 00  Accept: */*
		$a_00_4 = {41 63 63 65 70 74 2d 45 6e 63 6f 64 69 6e 67 3a 20 67 7a 69 70 2c 20 64 65 66 6c 61 74 65 } //01 00  Accept-Encoding: gzip, deflate
		$a_00_5 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 29 } //00 00  User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
	condition:
		any of ($a_*)
 
}