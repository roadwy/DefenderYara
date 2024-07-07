
rule Virus_Win32_Expiro_AB_MTB{
	meta:
		description = "Virus:Win32/Expiro.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 43 20 2b ca 29 c1 c1 e9 01 8b c3 83 c0 24 8b 00 01 d0 01 c8 8b 08 81 e1 90 01 04 c1 e1 02 8b 43 1c 03 c1 01 d0 8b 08 bf 90 01 04 03 ca 52 8d 1d 90 01 04 b8 00 40 09 00 56 03 de 51 54 57 50 53 ff d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}