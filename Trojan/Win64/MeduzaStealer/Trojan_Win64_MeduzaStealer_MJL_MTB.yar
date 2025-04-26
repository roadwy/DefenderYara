
rule Trojan_Win64_MeduzaStealer_MJL_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.MJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 41 f7 e0 c1 ea ?? 0f be c2 6b c8 32 41 8a c0 44 03 c7 2a c1 04 34 41 30 01 4c 03 cf 41 83 f8 08 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}