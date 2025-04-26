
rule Ransom_Win64_Cuba_FS_MTB{
	meta:
		description = "Ransom:Win64/Cuba.FS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 08 41 b8 00 00 02 00 48 8b d3 48 8b c8 41 ff 51 70 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}