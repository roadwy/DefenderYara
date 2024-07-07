
rule Virus_Win32_Flizzy_A{
	meta:
		description = "Virus:Win32/Flizzy.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5e 8b 7b 08 b9 95 00 00 00 56 8b d4 ad 8d 2c 07 c8 04 00 02 83 c4 08 8f 46 fc e2 f0 8b e2 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}