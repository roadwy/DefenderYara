
rule Trojan_BAT_FormBook_MBEH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {38 00 38 00 38 00 42 00 47 00 37 00 34 00 35 00 37 00 35 00 34 00 50 00 47 00 41 00 47 00 42 00 34 00 45 00 34 00 38 00 4e 00 39 00 00 13 69 00 64 00 50 00 70 00 75 00 48 00 59 00 31 00 39 } //1
		$a_01_1 = {70 00 73 00 61 00 } //1 psa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_FormBook_MBEH_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.MBEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 0a 11 09 6f ?? 00 00 0a 13 0b 16 13 0c 11 05 11 08 9a 72 86 0e 00 70 28 ?? 00 00 0a 13 0d 11 0d 2c 0d 00 12 0b 28 ?? 00 00 0a 13 0c 00 2b 42 11 05 11 08 9a 72 8a 0e 00 70 28 ?? 00 00 0a 13 0e 11 0e 2c 0d 00 12 0b 28 ?? 00 00 0a 13 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}