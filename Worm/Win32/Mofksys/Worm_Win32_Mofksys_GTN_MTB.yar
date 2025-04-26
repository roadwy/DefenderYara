
rule Worm_Win32_Mofksys_GTN_MTB{
	meta:
		description = "Worm:Win32/Mofksys.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {c5 24 5f 33 57 cd b9 d5 63 ef a8 b6 0e b2 f8 95 93 } //5
		$a_03_1 = {06 36 4d 14 f4 34 41 b4 71 a2 ?? ?? ?? ?? 95 e4 c4 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}