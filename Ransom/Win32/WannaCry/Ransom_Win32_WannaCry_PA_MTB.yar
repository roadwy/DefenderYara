
rule Ransom_Win32_WannaCry_PA_MTB{
	meta:
		description = "Ransom:Win32/WannaCry.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 77 61 6e 6e 61 63 72 79 } //1 .wannacry
		$a_01_1 = {4c 6f 63 61 6c 42 69 74 63 6f 69 6e 73 } //1 LocalBitcoins
		$a_01_2 = {40 50 6c 65 61 73 65 5f 52 65 61 64 5f 4d 65 40 2e 74 78 74 } //1 @Please_Read_Me@.txt
		$a_01_3 = {57 61 6e 6e 61 43 72 79 20 33 2e 30 20 20 40 50 6c 65 61 73 65 5f 52 65 61 64 5f 4d 65 40 } //1 WannaCry 3.0  @Please_Read_Me@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}