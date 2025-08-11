
rule Ransom_Win64_RALord_B{
	meta:
		description = "Ransom:Win64/RALord.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 00 00 55 c6 85 ?? 01 00 00 aa c6 85 ?? 01 00 00 00 c6 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}