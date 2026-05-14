
rule Trojan_Win32_Midie_AMI_MTB{
	meta:
		description = "Trojan:Win32/Midie.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 8b 55 08 8b 04 8a 03 45 fc 03 45 f4 c1 e0 03 8b 4d f8 8b 55 08 8b 0c 8a 03 4d fc 03 4d f4 c1 e9 1d 0b c1 89 45 fc 8b 55 f4 03 55 fc 89 55 f4 8b 45 c8 8b 54 85 d0 03 55 f4 8b 4d f4 d3 e2 8b 45 c8 8b 44 85 d0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}