
rule Trojan_BAT_Quasar_PSQV_MTB{
	meta:
		description = "Trojan:BAT/Quasar.PSQV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e a6 00 00 04 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 7e a6 00 00 04 72 d6 19 00 70 72 de 19 00 70 72 ec 19 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 7e a6 00 00 04 6f 83 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}