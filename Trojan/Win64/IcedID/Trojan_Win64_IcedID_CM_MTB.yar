
rule Trojan_Win64_IcedID_CM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 e0 00 00 00 0c 00 00 00 3a db 74 45 83 84 24 d4 00 00 00 03 c7 84 24 d8 00 00 00 2e 00 00 00 66 3b c0 74 ba 83 84 24 e4 00 00 00 26 c7 84 24 e8 00 00 00 32 00 00 00 66 3b d2 74 00 83 84 24 e8 00 00 00 28 c7 84 24 ec 00 00 00 01 00 00 00 eb 17 83 84 24 e0 00 00 00 00 c7 84 24 e4 00 00 00 12 00 00 00 3a c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}