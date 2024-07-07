
rule Ransom_Win64_Nokoyawa_A{
	meta:
		description = "Ransom:Win64/Nokoyawa.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {4e 4f 4b 4f 59 41 57 41 2e 65 78 90 01 01 20 28 45 6e 63 72 79 70 74 20 61 6c 6c 20 6c 6f 63 61 6c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}