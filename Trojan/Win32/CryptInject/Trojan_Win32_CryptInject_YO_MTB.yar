
rule Trojan_Win32_CryptInject_YO_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 18 8d 4c 24 28 90 0a 80 00 b1 72 68 90 01 03 00 50 89 90 01 04 00 c6 05 90 01 03 00 50 88 0d 90 01 03 00 c6 05 90 01 03 00 6f c6 05 90 01 03 00 65 c6 05 90 01 03 00 63 c6 05 90 01 03 00 00 c6 05 90 01 03 00 56 c6 05 90 01 03 00 69 88 0d 90 01 03 00 c6 05 90 01 03 00 75 c6 05 90 01 03 00 61 c6 05 90 01 03 00 6c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}