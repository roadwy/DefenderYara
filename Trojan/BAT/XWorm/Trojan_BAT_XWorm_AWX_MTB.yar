
rule Trojan_BAT_XWorm_AWX_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AWX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 06 8e 69 8d 16 00 00 01 0c 16 0d 2b 13 08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e7 } //2
		$a_01_1 = {52 00 65 00 73 00 56 00 6f 00 6c 00 6b 00 2e 00 65 00 78 00 65 00 } //1 ResVolk.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_XWorm_AWX_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.AWX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 3a 06 08 9a 28 ?? 00 00 0a 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0d 09 59 08 1f 0a 5d 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 04 07 11 04 6f ?? 00 00 0a 26 08 17 58 0c 08 06 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}