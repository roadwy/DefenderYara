
rule Trojan_Win64_Vidar_SLAE_MTB{
	meta:
		description = "Trojan:Win64/Vidar.SLAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 05 ee 9b 03 00 8d 48 ff 0f af c8 f6 c1 01 b8 58 b2 7a ac 41 0f 44 c5 83 3d d9 9b 03 00 0a 41 0f 4c c5 3d 8d 96 34 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}