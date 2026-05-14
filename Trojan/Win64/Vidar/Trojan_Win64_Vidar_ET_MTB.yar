
rule Trojan_Win64_Vidar_ET_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b d6 45 8d 86 6a 03 00 00 c1 ea 03 48 8b cb 85 d2 74 1f 0f 1f 80 00 00 00 00 49 8b c0 48 33 01 48 8d 49 08 48 c1 c8 05 48 89 41 f8 48 83 ea 01 75 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}