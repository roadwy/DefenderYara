
rule TrojanDownloader_O97M_IcedID_PNK_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PNK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6d 61 69 6e 2e 68 74 61 22 } //1 = "c:\users\public\main.hta"
		$a_01_1 = {2e 65 78 65 63 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 20 26 20 22 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6d 61 69 6e 2e 68 74 61 22 } //1 .exec frm.CommandButton1.Tag & " c:\users\public\main.hta"
		$a_01_2 = {43 61 6c 6c 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //1 Call frm.CommandButton1_Click
		$a_01_3 = {3d 20 22 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 74 6c 63 32 39 } //1 = "<div id='content'>fTtlc29
		$a_01_4 = {2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 } //1 .reverse().join('')
		$a_01_5 = {2e 54 69 6d 65 6f 75 74 20 3d 20 36 30 30 30 30 } //1 .Timeout = 60000
		$a_01_6 = {44 70 6a 49 44 49 7a 63 6e 5a 7a 5a 32 56 79 49 69 68 75 64 58 49 75 4b 53 4a 73 62 47 56 6f 63 79 35 30 63 47 6c 79 59 33 4e 33 49 69 68 30 59 32 56 71 59 6b 39 59 5a 58 5a 70 64 47 4e 42 49 48 64 6c 62 67 } //1 DpjIDIzcnZzZ2VyIihudXIuKSJsbGVocy50cGlyY3N3Iih0Y2VqYk9YZXZpdGNBIHdlbg
		$a_01_7 = {6d 4d 67 4d 6a 4e 79 64 6e 4e 6e 5a 58 49 69 4b 47 35 31 63 69 34 70 49 6d 78 73 5a 57 68 7a 4c 6e 52 77 61 58 4a 6a 63 33 63 69 4b 48 52 6a 5a 57 70 69 54 31 68 6c 64 6d 6c 30 59 30 45 67 64 32 56 75 } //1 mMgMjNydnNnZXIiKG51ci4pImxsZWhzLnRwaXJjc3ciKHRjZWpiT1hldml0Y0Egd2Vu
		$a_01_8 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_9 = {73 70 6c 69 74 28 27 7c 27 29 3b 76 61 72 } //1 split('|');var
		$a_01_10 = {50 72 69 6e 74 20 23 31 } //1 Print #1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=10
 
}