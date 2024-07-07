
rule Trojan_Win64_IcedID_ADF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 84 24 90 01 04 3a d2 74 90 01 01 b9 90 01 04 48 f7 f1 66 3b f6 74 90 01 01 89 84 24 90 01 04 48 90 01 04 66 3b c9 74 90 01 01 8b 40 90 01 01 48 90 01 04 66 3b c9 74 90 01 01 8b 4c 24 90 01 01 33 c8 66 3b ed 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}