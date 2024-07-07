
rule TrojanDownloader_Win32_Bancos_BV{
	meta:
		description = "TrojanDownloader:Win32/Bancos.BV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {6a 74 51 ff d6 8d 90 01 03 ff ff 6a 74 52 ff d6 8d 90 01 03 ff ff 6a 70 50 ff d6 8d 90 01 03 ff ff 6a 3a 51 ff d6 8d 90 01 03 ff ff 6a 2f 90 00 } //2
		$a_01_1 = {46 75 6e 63 5f 43 61 6d 69 6e 68 6f 5f 52 65 67 53 76 72 33 32 00 } //1 畆据䍟浡湩潨剟来癓㍲2
		$a_01_2 = {46 75 6e 63 5f 50 61 73 74 61 5f 53 79 73 74 65 6d 00 } //1 畆据偟獡慴卟獹整m
		$a_01_3 = {46 75 6e 63 5f 50 61 73 74 61 5f 57 69 6e 64 6f 77 73 00 } //1
		$a_01_4 = {41 67 75 61 72 64 61 72 00 } //1
		$a_01_5 = {2f 00 63 00 61 00 64 00 61 00 73 00 74 00 72 00 6f 00 2e 00 70 00 68 00 70 00 } //1 /cadastro.php
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}