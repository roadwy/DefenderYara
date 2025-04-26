
rule Trojan_BAT_Rozena_NRE_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 30 00 00 1f 40 28 ?? ?? 00 06 0c 07 16 08 07 8e 69 28 ?? ?? 00 0a 00 7e ?? ?? 00 0a 16 08 7e ?? ?? 00 0a 16 7e ?? ?? 00 0a 28 ?? ?? 00 06 } //5
		$a_01_1 = {6c 70 53 74 61 72 74 41 64 64 72 65 73 73 } //1 lpStartAddress
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}