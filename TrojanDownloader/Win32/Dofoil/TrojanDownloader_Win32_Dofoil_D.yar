
rule TrojanDownloader_Win32_Dofoil_D{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 f2 bc 67 53 6f 75 e4 8b 5f 08 8d b5 90 01 04 e8 90 01 04 8d bd 90 01 04 8d b5 90 01 04 e8 90 01 04 8d 85 90 01 04 50 ff 95 90 01 04 89 c3 90 00 } //1
		$a_01_1 = {46 32 06 aa e0 fa f7 d1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}