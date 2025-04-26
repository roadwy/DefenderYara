
rule Trojan_Win64_Dacic_MPF_MTB{
	meta:
		description = "Trojan:Win64/Dacic.MPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e0 c1 ea 05 0f be c2 6b c8 3a 41 0f b6 c0 2a c1 04 33 41 30 01 41 ff c0 4d 8d 49 ?? 41 83 f8 04 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}