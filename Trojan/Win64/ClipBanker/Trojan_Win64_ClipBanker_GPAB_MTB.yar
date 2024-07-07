
rule Trojan_Win64_ClipBanker_GPAB_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.GPAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 3d 89 a9 20 00 31 fe 40 88 34 18 48 ff c3 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}