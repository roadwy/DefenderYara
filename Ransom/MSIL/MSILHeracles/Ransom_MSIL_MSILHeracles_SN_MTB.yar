
rule Ransom_MSIL_MSILHeracles_SN_MTB{
	meta:
		description = "Ransom:MSIL/MSILHeracles.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 23 00 00 0a 17 73 24 00 00 0a 13 0b 11 07 19 73 21 00 00 0a 13 0c 2b 0a 11 0b 11 0d d2 6f 25 00 00 0a 11 0c 6f 26 00 00 0a 25 13 0d 15 33 e9 11 0c 6f 27 00 00 0a 11 0b 6f 27 00 00 0a 11 09 6f 27 00 00 0a 11 07 28 ?? 00 00 0a de 03 } //4
		$a_01_1 = {24 37 43 46 39 39 42 32 33 2d 43 45 30 37 2d 34 33 46 45 2d 38 32 37 39 2d 42 37 45 38 42 44 44 39 42 45 38 43 } //2 $7CF99B23-CE07-43FE-8279-B7E8BDD9BE8C
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}