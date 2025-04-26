
rule Trojan_Win64_Fabookie_CRTE_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.CRTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 40 ff 05 80 00 05 48 8d 40 02 48 83 e9 01 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}