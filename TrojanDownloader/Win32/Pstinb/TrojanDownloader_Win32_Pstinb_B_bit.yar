
rule TrojanDownloader_Win32_Pstinb_B_bit{
	meta:
		description = "TrojanDownloader:Win32/Pstinb.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 72 6c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 32 53 54 54 59 66 74 7a 2c 20 25 50 72 6f 67 72 61 6d 44 61 74 61 25 5c 90 02 20 2e 76 62 73 90 00 } //1
		$a_03_1 = {52 75 6e 20 25 50 72 6f 67 72 61 6d 44 61 74 61 25 5c 90 02 20 2e 76 62 73 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}