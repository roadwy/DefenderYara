
rule Trojan_BAT_Heracles_NHN_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 03 00 00 0a 2b 05 72 ?? ?? 00 70 26 2b 05 72 ?? ?? 00 70 20 ?? ?? 00 00 2b 05 72 ?? ?? 00 70 fe ?? ?? 00 2b 05 72 ?? ?? 00 70 00 2b 05 } //5
		$a_01_1 = {6e 4a 42 30 61 6e } //1 nJB0an
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}