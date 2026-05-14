
rule Trojan_BAT_FormBook_PAG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0b 07 06 72 ?? 00 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 6f ?? 00 00 0a 00 07 06 72 } //2
		$a_81_1 = {47 72 61 70 68 53 69 6d 75 6c 61 74 69 6f 6e 2e 41 67 72 65 67 61 72 41 72 63 6f 73 2e 72 65 73 6f 75 72 63 65 73 } //1 GraphSimulation.AgregarArcos.resources
		$a_81_2 = {24 32 65 62 30 35 31 37 62 2d 63 36 34 36 2d 34 36 31 33 2d 39 39 38 35 2d 63 39 35 63 37 31 32 61 36 38 64 61 } //1 $2eb0517b-c646-4613-9985-c95c712a68da
		$a_81_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}