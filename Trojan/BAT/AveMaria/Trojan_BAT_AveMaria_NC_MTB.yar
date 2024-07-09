
rule Trojan_BAT_AveMaria_NC_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 74 3f 00 70 d0 ?? ?? 00 02 28 ?? ?? 00 0a 6f ?? ?? 00 0a 73 ?? ?? 00 0a 0b } //5
		$a_01_1 = {49 6f 6c 68 65 } //1 Iolhe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}