
rule Trojan_Win64_Lazy_THK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.THK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c0 e1 02 49 8b d1 48 d3 ea 66 41 23 d6 42 ?? ?? 44 44 50 66 33 d0 41 0f b7 c0 66 41 2b c2 66 33 d0 66 ?? ?? 54 44 50 49 ff c0 49 83 f8 22 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}