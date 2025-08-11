
rule Trojan_Win64_Redcap_AB_MTB{
	meta:
		description = "Trojan:Win64/Redcap.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c9 eb 07 48 81 c1 60 98 00 00 48 81 f9 5f 98 00 00 7c f0 31 c9 eb 07 48 81 c1 30 34 00 00 48 81 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}