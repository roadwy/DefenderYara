
rule Trojan_Win64_Midie_GTC_MTB{
	meta:
		description = "Trojan:Win64/Midie.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {12 0e 6d 30 1b 97 fb 00 1c e0 58 95 } //5
		$a_01_1 = {41 32 f8 56 40 08 b4 54 1e 00 fe ff 40 d2 c7 66 0b de 40 1a f8 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}