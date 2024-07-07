
rule TrojanDownloader_Win32_Encriyoko_A{
	meta:
		description = "TrojanDownloader:Win32/Encriyoko.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 20 68 69 6a 61 63 6b 65 64 20 63 6f 6e 6e 65 63 74 69 6f 6e } //1 on hijacked connection
		$a_01_1 = {73 6f 75 72 63 65 73 6c 61 6e 67 2e 69 77 65 62 73 2e 77 73 2f 64 6f 77 6e 73 2f 7a 64 78 2e 74 67 7a } //1 sourceslang.iwebs.ws/downs/zdx.tgz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}