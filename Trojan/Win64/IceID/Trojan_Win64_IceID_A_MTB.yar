
rule Trojan_Win64_IceID_A_MTB{
	meta:
		description = "Trojan:Win64/IceID.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 30 ?? 30 41 ff e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}