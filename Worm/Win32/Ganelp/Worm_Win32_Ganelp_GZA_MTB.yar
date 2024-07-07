
rule Worm_Win32_Ganelp_GZA_MTB{
	meta:
		description = "Worm:Win32/Ganelp.GZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 0f be 0d 90 01 04 83 c1 02 88 8d 90 01 04 0f be 15 90 01 04 83 c2 15 88 95 90 00 } //5
		$a_01_1 = {40 00 fe b1 05 00 d4 f2 03 00 d0 f2 03 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}