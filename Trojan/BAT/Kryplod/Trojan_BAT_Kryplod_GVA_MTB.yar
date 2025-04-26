
rule Trojan_BAT_Kryplod_GVA_MTB{
	meta:
		description = "Trojan:BAT/Kryplod.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 07 8f cf 00 00 01 25 47 07 08 91 61 d2 52 07 08 8f cf 00 00 01 25 47 07 11 07 91 09 11 07 1a 5d 58 47 61 d2 61 d2 52 07 11 07 8f cf 00 00 01 25 47 07 08 91 61 d2 52 11 07 17 58 13 07 08 17 59 0c 11 07 08 32 b8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}