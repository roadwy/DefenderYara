
rule Worm_Win32_Mofei_ENAW_MTB{
	meta:
		description = "Worm:Win32/Mofei.ENAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a da fe c3 32 19 88 18 40 41 42 3b 54 24 10 } //3
		$a_01_1 = {8a 45 f4 83 c4 0c 88 04 1e 8a 45 f5 46 88 04 1e 46 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}