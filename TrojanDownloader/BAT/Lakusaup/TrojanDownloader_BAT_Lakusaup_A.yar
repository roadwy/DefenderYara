
rule TrojanDownloader_BAT_Lakusaup_A{
	meta:
		description = "TrojanDownloader:BAT/Lakusaup.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 00 75 00 67 00 61 00 72 00 73 00 79 00 6e 00 63 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 66 00 2f 00 44 00 } //1 sugarsync.com/pf/D
		$a_01_1 = {3f 00 64 00 69 00 72 00 65 00 63 00 74 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 3d 00 74 00 72 00 75 00 65 00 } //1 ?directDownload=true
		$a_01_2 = {55 73 65 72 73 5c 65 43 6f 4c 6f 47 79 5c 44 6f 63 75 6d 65 6e 74 73 } //1 Users\eCoLoGy\Documents
		$a_01_3 = {5c 00 78 00 75 00 70 00 61 00 65 00 75 00 2e 00 65 00 78 00 65 00 } //1 \xupaeu.exe
		$a_01_4 = {5c 00 61 00 64 00 62 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //1 \adbupdate.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}