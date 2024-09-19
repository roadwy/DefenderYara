
rule Trojan_BAT_ZgRAT_AC_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 0a 06 20 ?? ?? ?? 00 28 ?? 00 00 06 6f ?? 00 00 0a 0b d0 ?? 00 00 01 28 ?? 00 00 0a 07 20 ?? ?? ?? 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 26 07 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}