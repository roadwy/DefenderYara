
rule Trojan_Win64_Lazy_AL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c2 69 d0 93 01 00 01 0f b6 41 ff e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}