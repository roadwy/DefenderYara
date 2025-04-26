
rule Ransom_Win64_Nokonoko_ZB{
	meta:
		description = "Ransom:Win64/Nokonoko.ZB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {ba e2 08 85 99 48 8d 0d d8 3a 00 00 e8 cb 2c 00 00 45 33 c9 45 33 c0 48 8b d3 49 8b cc ff d0 } //1
		$a_01_1 = {ba d0 03 5c 09 } //1
		$a_01_2 = {ba e2 08 85 99 } //1
		$a_01_3 = {ba 12 56 e9 cc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}