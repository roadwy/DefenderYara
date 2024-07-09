
rule Trojan_BAT_Heracle_KAG_MTB{
	meta:
		description = "Trojan:BAT/Heracle.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 2b 06 20 ?? ?? ?? ?? 25 26 08 20 ?? ?? ?? ?? 5a 61 2b a4 07 16 31 08 } //5
		$a_01_1 = {6b 67 77 75 72 68 6d 61 6a 6b 64 6f 65 7a 70 } //1 kgwurhmajkdoezp
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}