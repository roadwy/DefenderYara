
rule Trojan_Win64_Vidar_PAHO_MTB{
	meta:
		description = "Trojan:Win64/Vidar.PAHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 18 48 8b 8c 24 e8 00 00 00 48 6b d1 1d 48 89 c3 48 b8 51 39 bb 85 5f 8d 89 f4 48 89 d6 48 f7 ea 48 8d 04 16 48 c1 f8 06 48 89 f2 48 c1 fe 3f 48 29 f0 48 6b c0 43 48 29 c2 48 89 13 48 8d 41 01 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}