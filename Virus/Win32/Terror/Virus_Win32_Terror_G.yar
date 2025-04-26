
rule Virus_Win32_Terror_G{
	meta:
		description = "Virus:Win32/Terror.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 81 e9 05 20 40 00 51 5d 8b f5 83 fe 00 74 28 90 90 90 90 68 4d 07 00 00 8d 8d 43 20 40 00 5a 66 8b 19 66 03 9d 05 20 40 00 66 f7 d3 66 89 19 83 c1 02 83 ea 01 75 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}