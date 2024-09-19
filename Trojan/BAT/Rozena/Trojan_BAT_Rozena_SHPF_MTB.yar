
rule Trojan_BAT_Rozena_SHPF_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SHPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 0c 7e ?? ?? ?? 0a 08 20 00 30 00 00 1f 40 28 ?? ?? ?? 06 0d 16 13 06 2b 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}