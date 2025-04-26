
rule Ransom_Win64_Crytox_E{
	meta:
		description = "Ransom:Win64/Crytox.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 ff c9 41 8b 34 88 48 03 f2 4d 33 c9 48 33 ?? ac 41 c1 c9 0b 44 03 c8 3a c4 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}