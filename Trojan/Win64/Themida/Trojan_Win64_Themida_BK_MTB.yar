
rule Trojan_Win64_Themida_BK_MTB{
	meta:
		description = "Trojan:Win64/Themida.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 1c bf b4 7a 30 03 85 d1 3e 70 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}