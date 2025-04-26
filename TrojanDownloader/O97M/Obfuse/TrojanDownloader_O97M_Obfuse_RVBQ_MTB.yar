
rule TrojanDownloader_O97M_Obfuse_RVBQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2d 6e 6f 70 2d 65 70 62 79 70 61 73 73 2d 63 28 22 2b 22 69 22 2b 22 27 22 2b 22 77 22 2b 22 27 22 2b 22 72 22 2b 22 28 27 22 61 6c 6f 32 3d 22 68 74 74 70 } //1 powershell-nop-epbypass-c("+"i"+"'"+"w"+"'"+"r"+"('"alo2="http
		$a_01_1 = {3d 67 65 74 6f 62 6a 65 63 74 28 22 6e 65 77 3a 66 39 33 35 64 63 32 32 2d 31 63 66 30 2d 31 31 64 30 2d 61 64 62 39 2d 30 30 63 30 34 66 64 35 38 61 30 62 22 29 6d 65 69 6e 6b 6f 6e 68 75 6e 2e 65 78 65 63 61 6c 6f 33 65 6e 64 73 75 62 } //1 =getobject("new:f935dc22-1cf0-11d0-adb9-00c04fd58a0b")meinkonhun.execalo3endsub
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //1 workbook_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}