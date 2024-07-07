
rule Trojan_Win64_Tedy_AMBE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 c8 49 8b c7 48 f7 e1 48 c1 ea 05 48 8d 04 d2 48 c1 e0 02 48 2b c8 42 0f b6 04 21 88 04 1e 48 ff c6 48 83 fe } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}