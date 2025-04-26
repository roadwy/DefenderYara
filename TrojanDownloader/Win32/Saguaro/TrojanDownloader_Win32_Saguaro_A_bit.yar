
rule TrojanDownloader_Win32_Saguaro_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Saguaro.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 6f 00 73 00 63 00 6f 00 77 00 31 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 70 00 72 00 6f 00 78 00 79 00 2f 00 61 00 73 00 73 00 6e 00 6f 00 2e 00 65 00 78 00 65 00 } //1 http://moscow1.online/proxy/assno.exe
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 6f 00 73 00 63 00 6f 00 77 00 31 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 70 00 72 00 6f 00 78 00 79 00 2f 00 73 00 6b 00 61 00 70 00 6f 00 6c 00 61 00 6e 00 64 00 2e 00 65 00 78 00 65 00 } //1 http://moscow1.online/proxy/skapoland.exe
		$a_01_2 = {5c 00 61 00 73 00 73 00 6e 00 6f 00 2e 00 73 00 69 00 67 00 } //1 \assno.sig
		$a_01_3 = {5c 00 73 00 6b 00 61 00 70 00 6f 00 6c 00 61 00 6e 00 64 00 2e 00 73 00 69 00 67 00 } //1 \skapoland.sig
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}