
rule Trojan_BAT_Remcos_MBWI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 2b 37 02 28 ?? 00 00 0a 0b 12 01 28 ?? 00 00 0a 17 58 20 00 01 00 00 5d 02 28 ?? 00 00 0a 0b 12 01 28 ?? 00 00 0a 02 } //2
		$a_01_1 = {70 77 73 67 6c 33 2e 50 72 6f 70 65 72 74 69 } //1 pwsgl3.Properti
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}