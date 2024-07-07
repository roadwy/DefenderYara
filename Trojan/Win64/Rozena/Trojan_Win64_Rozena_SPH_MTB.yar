
rule Trojan_Win64_Rozena_SPH_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 0c 11 80 f1 7e 88 0a 41 ff c0 48 8d 52 01 49 63 c0 48 3b c7 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}