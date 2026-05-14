
rule Ransom_Win64_BlackSpider_PA_MTB{
	meta:
		description = "Ransom:Win64/BlackSpider.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 } //1 Go build
		$a_01_1 = {52 33 41 44 4d 33 2e 74 78 74 } //1 R3ADM3.txt
		$a_01_2 = {5b 42 4c 34 43 4b 20 53 50 31 44 33 52 20 52 41 4e 53 4f 4d 57 41 52 45 5d } //3 [BL4CK SP1D3R RANSOMWARE]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}