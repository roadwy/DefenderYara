
rule Trojan_Win64_Tedy_WD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.WD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 d3 4d 62 10 41 f7 e0 c1 ea 03 0f be c2 6b c8 7d 41 0f b6 c0 2a c1 2c 71 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 10 7c d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}