
rule Trojan_Win64_Lazy_PGL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 7d a0 07 48 8d 4d 88 4c 89 74 24 30 ba ?? ?? ?? ?? 48 0f 47 4d 88 45 33 c9 45 33 c0 c7 44 24 28 ?? ?? ?? ?? c7 44 24 20 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}