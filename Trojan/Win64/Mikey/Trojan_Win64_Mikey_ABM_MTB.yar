
rule Trojan_Win64_Mikey_ABM_MTB{
	meta:
		description = "Trojan:Win64/Mikey.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 1f 03 d0 0f be c2 6b c8 ?? 41 8a c0 44 03 c7 2a c1 40 02 c6 41 30 01 4c 03 cf 41 83 f8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}