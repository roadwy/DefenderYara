
rule Trojan_Win64_IcedID_GZ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 6d d4 44 89 4d d4 8b 45 48 41 33 c2 89 45 48 44 89 6d d4 44 89 4d d4 48 8b 45 e8 0f b7 08 8b 45 48 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}