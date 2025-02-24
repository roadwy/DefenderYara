
rule Trojan_Win64_Dacic_TFZ_MTB{
	meta:
		description = "Trojan:Win64/Dacic.TFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 ?? 0f b6 c1 ff c1 2a c2 04 36 41 30 40 ff 83 f9 1d 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}