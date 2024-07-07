
rule Worm_Win32_Gamarue_T{
	meta:
		description = "Worm:Win32/Gamarue.T,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 83 f1 4e 90 02 02 39 90 01 05 76 14 8a 14 30 32 d1 80 c2 90 01 01 88 14 30 46 3b 35 90 01 04 72 ec ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}