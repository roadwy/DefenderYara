
rule Virus_Win32_Expiro_DC_MTB{
	meta:
		description = "Virus:Win32/Expiro.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 53 55 56 57 e8 90 01 04 59 81 e9 90 01 04 bf 90 01 04 51 f7 91 f4 01 00 00 f7 91 d8 01 00 00 81 69 04 84 21 8d 64 81 b1 84 03 00 00 10 68 24 6a 81 b1 90 01 04 b3 02 c7 46 81 71 30 c1 14 44 57 f7 91 08 03 00 00 81 a9 c8 02 00 00 78 7a 6e 25 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}