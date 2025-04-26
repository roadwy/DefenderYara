
rule Trojan_Win64_Sodinokibi_MTB{
	meta:
		description = "Trojan:Win64/Sodinokibi!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec e9 90 0a 07 00 55 8b ec 90 13 8b 75 08 90 13 8b 7d 0c 90 13 8b 55 10 90 13 b1 07 90 13 ac e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}