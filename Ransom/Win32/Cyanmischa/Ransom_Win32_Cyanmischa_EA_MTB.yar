
rule Ransom_Win32_Cyanmischa_EA_MTB{
	meta:
		description = "Ransom:Win32/Cyanmischa.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 34 5a 8a 04 19 88 46 01 8b 3d ?? ?? ?? ?? c6 04 5f 0b 43 81 fb d0 07 00 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}