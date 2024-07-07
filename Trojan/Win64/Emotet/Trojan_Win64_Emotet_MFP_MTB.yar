
rule Trojan_Win64_Emotet_MFP_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 48 01 d0 48 c1 e0 06 48 89 c2 48 8b 85 38 01 00 00 48 01 d0 48 89 85 b0 00 00 00 48 8b 85 b0 00 00 00 8b 40 3c 48 63 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}