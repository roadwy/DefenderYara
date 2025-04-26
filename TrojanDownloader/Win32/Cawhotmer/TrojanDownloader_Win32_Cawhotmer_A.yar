
rule TrojanDownloader_Win32_Cawhotmer_A{
	meta:
		description = "TrojanDownloader:Win32/Cawhotmer.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 00 65 00 72 00 61 00 64 00 6f 00 61 00 76 00 69 00 73 00 6f 00 5c 00 } //1 geradoaviso\
		$a_03_1 = {2f 00 73 00 70 00 6c 00 75 00 73 00 2f 00 [0-02] 2e 00 61 00 73 00 70 00 3f 00 6d 00 6b 00 6e 00 61 00 3d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}