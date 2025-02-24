
rule Ransom_Win32_Flocked_YAD_MTB{
	meta:
		description = "Ransom:Win32/Flocked.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 0c bb 8b 7d 0c 8b 45 fc 31 0f 8b 4c 83 08 8b c1 8b b3 38 20 00 } //11
	condition:
		((#a_01_0  & 1)*11) >=11
 
}