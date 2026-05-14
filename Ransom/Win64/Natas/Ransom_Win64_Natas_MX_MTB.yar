
rule Ransom_Win64_Natas_MX_MTB{
	meta:
		description = "Ransom:Win64/Natas.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 c7 f4 48 03 fb 33 db 48 8d 4f 0c 48 8b c7 48 3b f9 77 10 81 38 12 5e d9 57 74 7a 48 ff c0 48 3b c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}