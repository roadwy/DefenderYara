
rule Ransom_MSIL_Gommyrypt_AGO_MTB{
	meta:
		description = "Ransom:MSIL/Gommyrypt.AGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 1d 08 72 ?? 08 00 70 07 09 91 8c 20 00 00 01 28 4b 00 00 0a 6f 4c 00 00 0a 26 09 17 58 0d 09 07 8e 69 32 dd } //2
		$a_01_1 = {41 00 64 00 6d 00 6f 00 6f 00 6f 00 6f 00 6e 00 } //1 Admoooon
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}