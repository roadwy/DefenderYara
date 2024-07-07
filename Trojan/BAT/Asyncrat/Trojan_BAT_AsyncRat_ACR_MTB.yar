
rule Trojan_BAT_AsyncRat_ACR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0d 2b 21 11 06 09 11 06 09 91 20 24 6d 6d ef 20 70 33 9b 7e 58 20 39 a0 08 6e 61 61 09 61 d2 9c 09 17 58 0d 09 11 06 8e 69 fe 04 2d d6 } //2
		$a_01_1 = {4d 00 6a 00 43 00 6b 00 31 00 78 00 2e 00 65 00 78 00 65 00 } //1 MjCk1x.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}