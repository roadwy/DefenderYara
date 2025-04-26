
rule TrojanDownloader_Win32_Sownada_A{
	meta:
		description = "TrojanDownloader:Win32/Sownada.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3c 00 2f 00 64 00 75 00 72 00 75 00 6d 00 3e 00 } //1 </durum>
		$a_01_1 = {3c 00 2f 00 73 00 69 00 74 00 65 00 3e 00 } //1 </site>
		$a_01_2 = {73 00 6f 00 6e 00 75 00 6e 00 64 00 61 00 20 00 6f 00 6c 00 64 00 75 00 } //1 sonunda oldu
		$a_01_3 = {5c 00 6d 00 73 00 6e 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 } //1 \msnservices
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}