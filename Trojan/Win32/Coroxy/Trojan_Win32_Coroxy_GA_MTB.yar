
rule Trojan_Win32_Coroxy_GA_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 04 3b 30 06 46 43 49 80 fb 28 75 } //1
		$a_01_1 = {02 ca 36 8a 8c 29 00 fc ff ff 30 0e 46 4f 75 cc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}