
rule Ransom_MSIL_Pykaro_A{
	meta:
		description = "Ransom:MSIL/Pykaro.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 5b 33 4e 11 04 1f 5d 6f cd 00 00 0a 17 2c b7 } //1
		$a_01_1 = {6b 61 72 6f 2e 65 78 65 00 6b 61 72 6f 00 3c 4d 6f 64 75 6c 65 3e } //1 慫潲攮數欀牡o䴼摯汵㹥
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}