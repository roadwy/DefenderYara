
rule Virus_Win32_Expiro_MK_bit{
	meta:
		description = "Virus:Win32/Expiro.MK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d3 83 c2 30 8b 12 8b 02 81 e0 df 00 df 00 8b 52 0c c1 e2 08 01 c2 c1 e2 02 } //1
		$a_03_1 = {40 8b 06 85 c0 35 90 01 04 39 c3 89 03 8d 06 4a 4a 4a 83 c3 04 81 c6 04 00 00 00 4a 85 d2 75 df 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}