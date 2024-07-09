
rule Trojan_BAT_Remcos_AGCM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AGCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 } //2
		$a_01_1 = {52 00 69 00 69 00 63 00 68 00 69 00 53 00 68 00 61 00 72 00 70 00 } //1 RiichiSharp
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}