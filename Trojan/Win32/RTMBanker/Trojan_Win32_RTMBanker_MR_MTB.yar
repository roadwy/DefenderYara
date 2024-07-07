
rule Trojan_Win32_RTMBanker_MR_MTB{
	meta:
		description = "Trojan:Win32/RTMBanker.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 f6 2b 37 f7 de 83 ef 90 01 01 83 ee 90 01 01 c1 ce 90 01 01 29 d6 83 ee 90 01 01 29 d2 29 f2 f7 da c1 c2 90 01 01 d1 ca 90 01 02 8f 01 01 31 83 e9 90 01 01 83 eb 90 01 01 8d 5b 90 01 01 83 fb 90 01 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}