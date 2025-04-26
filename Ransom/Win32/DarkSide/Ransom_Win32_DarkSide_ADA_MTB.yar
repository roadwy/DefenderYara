
rule Ransom_Win32_DarkSide_ADA_MTB{
	meta:
		description = "Ransom:Win32/DarkSide.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 9a bf 0b 41 00 8a 82 bf 0b 41 00 8a ab be 0b 41 00 88 83 be 0b 41 00 88 aa bf 0b 41 00 02 c5 47 8a 80 be 0b 41 00 fe c2 30 07 fe c9 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}