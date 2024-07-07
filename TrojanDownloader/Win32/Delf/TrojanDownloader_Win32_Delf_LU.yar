
rule TrojanDownloader_Win32_Delf_LU{
	meta:
		description = "TrojanDownloader:Win32/Delf.LU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 31 37 33 70 66 2e 63 6e 2f 3f } //1 .173pf.cn/?
		$a_01_1 = {39 38 2e 31 32 36 2e 32 30 38 2e 38 33 2f 67 65 74 2e 61 73 70 3f } //1 98.126.208.83/get.asp?
		$a_01_2 = {7d 61 61 65 2f 3a 3a 26 21 26 2c 26 3b 76 7b 3a 6d 7c 74 7a 3b 70 6d 70 } //2 }aae/::&!&,&;v{:m|tz;pmp
		$a_01_3 = {30 54 59 59 40 46 50 47 46 45 47 5a 53 5c 59 50 30 49 6d 7c 74 7a 3b 70 6d 70 } //2 0TYY@FPGFEGZS\YP0Im|tz;pmp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=5
 
}