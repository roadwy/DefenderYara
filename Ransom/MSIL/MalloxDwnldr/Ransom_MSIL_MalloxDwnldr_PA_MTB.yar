
rule Ransom_MSIL_MalloxDwnldr_PA_MTB{
	meta:
		description = "Ransom:MSIL/MalloxDwnldr.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 45 02 28 ?? ?? ?? ?? 74 ?? ?? ?? ?? 0b 07 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 07 6f ?? ?? ?? ?? 0c 73 ?? ?? ?? ?? 0d 08 6f ?? ?? ?? ?? 09 6f ?? ?? ?? ?? 09 6f ?? ?? ?? ?? 13 04 11 04 } //1
		$a_03_1 = {16 0a 2b 3b 02 28 ?? ?? ?? ?? 74 ?? ?? ?? ?? 0b 07 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 07 6f ?? ?? ?? ?? 0c 73 ?? ?? ?? ?? 0d 08 6f ?? ?? ?? ?? 09 6f ?? ?? ?? ?? 09 6f ?? ?? ?? ?? 13 04 11 04 } //1
		$a_01_2 = {94 9e 11 0a 11 06 11 08 9e 11 0a 11 0a 11 04 94 11 0a 11 06 94 58 20 00 01 00 00 5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*3) >=4
 
}