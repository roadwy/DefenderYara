
rule Trojan_BAT_Rhadamanthus_CAK_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthus.CAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1c 09 11 04 18 5b 07 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32 df } //3
		$a_01_1 = {63 00 6c 00 65 00 61 00 6e 00 69 00 6e 00 67 00 2e 00 68 00 6f 00 6d 00 65 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 70 00 63 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 2f 00 43 00 6d 00 6c 00 76 00 67 00 75 00 63 00 65 00 6b 00 69 00 2e 00 70 00 6e 00 67 00 } //2 cleaning.homesecuritypc.com/packages/Cmlvguceki.png
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}