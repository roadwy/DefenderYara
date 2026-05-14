
rule Trojan_Win64_Shelma_MK_MTB{
	meta:
		description = "Trojan:Win64/Shelma.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {3a 69 24 02 53 8b 2a 1c de 33 58 24 dc 1f 55 } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}