
rule Trojan_Win32_Zenpack_NEAC_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 6c 61 63 65 65 6d 75 6c 74 69 70 6c 79 2c 57 74 68 65 55 6e 74 6f } //2 placeemultiply,WtheUnto
		$a_01_1 = {46 6f 72 6d 79 65 61 72 73 69 73 } //2 Formyearsis
		$a_01_2 = {52 58 66 6f 72 74 68 2e } //2 RXforth.
		$a_01_3 = {61 6f 75 72 63 6d 69 64 73 74 } //2 aourcmidst
		$a_01_4 = {47 58 75 6e 64 65 72 70 73 61 77 74 65 68 61 64 30 } //2 GXunderpsawtehad0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}