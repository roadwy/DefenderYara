
rule Trojan_Win32_Crysan_SIBC_MTB{
	meta:
		description = "Trojan:Win32/Crysan.SIBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 00 00 00 00 8a 8b 90 01 04 81 fb 90 01 04 74 90 01 01 f6 d1 80 c1 90 01 01 80 f1 90 01 01 80 c1 90 01 01 80 f1 90 01 01 88 8b 90 1b 00 83 c3 01 90 18 8a 8b 90 1b 00 81 fb 90 1b 01 90 18 66 59 5b 8d 45 90 01 01 50 6a 40 68 90 1b 01 68 90 1b 00 ff 15 90 01 04 6a 00 68 90 1b 00 6a 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}