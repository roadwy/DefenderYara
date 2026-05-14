
rule Trojan_Win64_QuasarRAT_ABQR_MTB{
	meta:
		description = "Trojan:Win64/QuasarRAT.ABQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b d0 41 8d 40 ?? 0f b6 0c 3a 41 2a c8 41 ff c0 80 e9 ?? 32 c8 c0 c9 ?? 88 0c 3a 41 81 f8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}