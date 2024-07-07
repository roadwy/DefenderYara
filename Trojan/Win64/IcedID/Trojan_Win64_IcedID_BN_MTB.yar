
rule Trojan_Win64_IcedID_BN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 28 44 8b 4c 24 48 66 3b db 74 00 4c 8b 44 24 40 48 8b 54 24 38 3a c0 74 d4 33 c0 48 83 c4 28 eb db 4c 87 db 48 f7 d5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}