
rule Ransom_Win32_LockBit_AB{
	meta:
		description = "Ransom:Win32/LockBit.AB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_01_1 = {8b 55 0c 8b 75 08 66 ad 90 66 83 f8 41 72 0b 66 83 f8 5a 77 05 66 83 c8 20 90 33 c9 b9 30 00 00 00 8d 0c 4d 01 00 00 00 02 f1 2a f1 33 c9 b9 06 00 00 00 8d 0c 4d 01 00 00 00 d3 ca 03 d0 90 85 c0 75 c3 } //00 00 
		$a_00_2 = {5d 04 00 00 ef 1c 05 80 5c 2d } //00 00 
	condition:
		any of ($a_*)
 
}