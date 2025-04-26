
rule Trojan_BAT_Injuke_MBYN_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MBYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {13 04 09 11 04 16 11 04 8e 69 6f 0a } //1
		$a_01_1 = {59 6c 69 73 6d 6a 7a 61 67 77 00 48 65 6c 70 65 } //5 汙獩橭慺睧䠀汥数
		$a_01_2 = {53 00 4c 00 4c 00 31 00 43 00 79 00 46 00 54 00 39 00 37 00 46 00 4f 00 30 00 4d 00 49 00 69 00 74 00 4e 00 6e 00 78 00 6c 00 51 00 } //5 SLL1CyFT97FO0MIitNnxlQ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=11
 
}