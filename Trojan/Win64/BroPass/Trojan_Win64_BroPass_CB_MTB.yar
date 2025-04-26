
rule Trojan_Win64_BroPass_CB_MTB{
	meta:
		description = "Trojan:Win64/BroPass.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 8b ca 41 b8 00 30 00 00 48 8b d1 48 8b c8 48 ff 25 } //1
		$a_01_1 = {4f 00 55 00 54 00 50 00 55 00 54 00 5f 00 42 00 49 00 4e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}