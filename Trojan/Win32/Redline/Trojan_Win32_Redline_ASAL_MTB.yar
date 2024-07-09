
rule Trojan_Win32_Redline_ASAL_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 06 8b c6 f7 f3 8a 82 [0-04] 32 c1 8b 4d 08 88 04 0e e8 [0-04] 46 83 c4 08 3b f7 72 } //1
		$a_01_1 = {7a 61 44 46 52 45 48 4a 54 59 55 } //1 zaDFREHJTYU
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}