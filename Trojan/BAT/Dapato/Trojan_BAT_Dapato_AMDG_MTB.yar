
rule Trojan_BAT_Dapato_AMDG_MTB{
	meta:
		description = "Trojan:BAT/Dapato.AMDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 36 11 34 16 6f ?? 00 00 0a 61 d2 13 36 20 ?? ?? ?? ?? 7e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}