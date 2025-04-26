
rule Trojan_Win64_Sonbokli_GVA_MTB{
	meta:
		description = "Trojan:Win64/Sonbokli.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c2 48 8b 45 18 48 01 d0 0f b6 08 48 8b 55 10 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 20 72 bc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}