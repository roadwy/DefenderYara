
rule Trojan_BAT_Remcos_PDZF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PDZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 18 06 08 2b 09 06 18 6f ?? ?? ?? 0a 2b 07 6f ?? ?? ?? 0a 2b f0 02 0d 2b 03 26 2b e5 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}