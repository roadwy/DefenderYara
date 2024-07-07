
rule Trojan_Win32_Zenpack_NEAE_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.NEAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 65 70 69 6e 67 79 61 62 75 6e 64 61 6e 74 6c 79 } //2 Creepingyabundantly
		$a_01_1 = {62 65 34 74 68 65 79 2e 72 65 2e 31 74 68 65 69 72 2e 4b 66 61 63 65 } //2 be4they.re.1their.Kface
		$a_01_2 = {37 63 72 65 65 70 65 74 68 69 6e 6f } //2 7creepethino
		$a_01_3 = {75 6e 64 65 72 69 73 6e 2e 74 6d 61 64 65 73 61 77 66 73 65 65 64 56 } //2 underisn.tmadesawfseedV
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}