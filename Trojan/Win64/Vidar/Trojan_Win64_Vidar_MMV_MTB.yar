
rule Trojan_Win64_Vidar_MMV_MTB{
	meta:
		description = "Trojan:Win64/Vidar.MMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 31 0f b6 c1 ff c1 2a c2 04 35 41 30 40 ff 83 f9 21 7c d3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}