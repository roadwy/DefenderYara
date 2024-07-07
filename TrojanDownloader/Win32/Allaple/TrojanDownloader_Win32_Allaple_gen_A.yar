
rule TrojanDownloader_Win32_Allaple_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Allaple.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 73 74 61 74 65 2e 63 6f 2e 75 73 2f 63 6f 6e 73 6c 69 6e 65 2f 63 6f 6d 70 6c 61 69 6e 74 2e 70 64 66 } //5 .state.co.us/consline/complaint.pdf
		$a_01_1 = {77 77 77 2e 70 6b 73 2d 6a 61 6b 61 72 74 61 2e 6f 72 2e 69 64 2f 70 69 63 73 2f 64 65 66 61 75 6c 74 } //5 www.pks-jakarta.or.id/pics/default
		$a_01_2 = {65 6d 61 69 6c 5f 64 6f 77 6e 6c 6f 61 64 65 72 } //1 email_downloader
		$a_03_3 = {6a ff 6a 00 e8 90 01 03 ff 8b d8 85 db 74 0c e8 90 01 03 ff 3d b7 00 00 00 75 0d 53 e8 90 00 } //10
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_03_3  & 1)*10) >=21
 
}