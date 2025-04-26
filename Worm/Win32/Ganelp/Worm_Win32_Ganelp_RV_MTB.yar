
rule Worm_Win32_Ganelp_RV_MTB{
	meta:
		description = "Worm:Win32/Ganelp.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 94 83 c0 2f 99 b9 5e 00 00 00 f7 f9 8b 45 08 03 45 98 8a 4c 15 a0 88 08 eb 02 } //1
		$a_01_1 = {8b 4d 10 c1 e1 03 39 4d fc 7d 64 8b 45 fc 99 83 e2 07 03 c2 c1 f8 03 8b 55 0c 0f be 04 02 8b 4d fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}