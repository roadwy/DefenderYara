
rule Trojan_Win32_DCRat_MX_MTB{
	meta:
		description = "Trojan:Win32/DCRat.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 8b c7 c1 f8 05 8d 34 85 60 3f 42 00 8b 06 83 e7 1f c1 e7 06 03 c7 8a 58 24 02 db d0 fb } //1
		$a_01_1 = {6c 00 69 00 62 00 47 00 4c 00 45 00 53 00 76 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 libGLESv2.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}