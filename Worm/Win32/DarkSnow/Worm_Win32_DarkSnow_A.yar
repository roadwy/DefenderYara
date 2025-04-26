
rule Worm_Win32_DarkSnow_A{
	meta:
		description = "Worm:Win32/DarkSnow.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c2 f8 00 00 00 8b da 83 c3 28 81 3a 62 6c 61 63 75 0e 81 7a 04 6b 69 63 65 75 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}