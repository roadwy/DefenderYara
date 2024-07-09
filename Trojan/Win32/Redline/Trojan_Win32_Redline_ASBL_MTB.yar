
rule Trojan_Win32_Redline_ASBL_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d6 80 34 2f ?? ff d6 80 04 2f ?? ff d6 80 2c 2f ?? ff d6 80 04 2f ?? 47 3b fb 0f 82 } //1
		$a_01_1 = {77 61 72 6e 69 6e 67 20 69 73 20 74 68 65 20 69 64 65 6e 74 69 66 79 } //1 warning is the identify
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}