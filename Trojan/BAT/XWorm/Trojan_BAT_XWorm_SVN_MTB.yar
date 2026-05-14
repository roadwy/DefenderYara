
rule Trojan_BAT_XWorm_SVN_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 00 43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //2 XClient.exe
		$a_01_1 = {72 61 6e 67 65 44 65 63 6f 64 65 72 } //2 rangeDecoder
		$a_01_2 = {50 69 78 65 6c 46 6f 72 6d 61 74 } //2 PixelFormat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}