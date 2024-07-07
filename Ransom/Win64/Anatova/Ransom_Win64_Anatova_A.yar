
rule Ransom_Win64_Anatova_A{
	meta:
		description = "Ransom:Win64/Anatova.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 00 64 00 27 00 71 00 74 00 74 00 66 00 63 00 6a 00 6e 00 69 00 27 00 63 00 62 00 6b 00 62 00 73 00 62 00 27 00 74 00 6f 00 66 00 63 00 68 00 70 00 74 00 27 00 28 00 66 00 6b 00 6b 00 27 00 28 00 76 00 72 00 6e 00 62 00 73 00 } //1 (d'qttfcjni'cbkbsb'tofchpt'(fkk'(vrnbs
		$a_01_1 = {6b 61 25 70 76 25 4a 4b 40 25 4f 55 42 25 43 4c 49 40 25 4a 4b 49 5c 25 68 64 7d 25 37 35 35 6e 67 25 71 6a 25 61 } //1 ka%pv%JK@%OUB%CLI@%JKI\%hd}%755ng%qj%a
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}