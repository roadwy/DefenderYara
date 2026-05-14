
rule Trojan_Win64_Vidar_GY_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 00 fc 41 0f b6 c4 0f b6 84 04 d0 01 00 00 43 30 44 35 00 49 ff c6 49 83 fe 40 0f 84 af fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}