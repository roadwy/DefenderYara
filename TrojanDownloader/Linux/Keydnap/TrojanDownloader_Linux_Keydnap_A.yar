
rule TrojanDownloader_Linux_Keydnap_A{
	meta:
		description = "TrojanDownloader:Linux/Keydnap.A,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 61 6c 6c 20 54 65 72 6d 69 6e 61 6c } //1 killall Terminal
		$a_00_1 = {2f 74 6d 70 2f 63 6f 6d 2e 61 70 70 6c 65 2e 69 63 6c 6f 75 64 73 79 6e 63 64 } //1 /tmp/com.apple.icloudsyncd
		$a_00_2 = {6c 6f 76 65 66 72 6f 6d 73 63 72 61 74 63 68 2e 63 61 2f 77 70 2d 61 64 6d 69 6e 2f 43 56 64 65 74 61 69 6c 73 2e 64 6f 63 } //1 lovefromscratch.ca/wp-admin/CVdetails.doc
		$a_00_3 = {54 57 39 7a 64 43 42 44 62 32 31 74 62 32 34 67 53 57 35 30 5a 58 4a 32 61 57 56 33 49 46 46 } //1 TW9zdCBDb21tb24gSW50ZXJ2aWV3IFF
		$a_00_4 = {61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 35 75 64 57 64 6e 5a 58 52 7a 4e 44 45 78 4c 6d 4e 76 62 53 39 70 59 32 78 76 64 57 52 7a 65 57 35 6a 5a 41 3d 3d } //1 aHR0cDovL3d3dy5udWdnZXRzNDExLmNvbS9pY2xvdWRzeW5jZA==
		$a_00_5 = {54 33 5a 6c 63 69 42 30 61 47 55 67 64 32 56 6c 61 32 56 75 5a 43 77 67 64 47 68 6c 49 47 5a 70 63 6e 4e 30 } //1 T3ZlciB0aGUgd2Vla2VuZCwgdGhlIGZpcnN0
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}