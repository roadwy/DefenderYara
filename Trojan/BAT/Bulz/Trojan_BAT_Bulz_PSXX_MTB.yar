
rule Trojan_BAT_Bulz_PSXX_MTB{
	meta:
		description = "Trojan:BAT/Bulz.PSXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 0a 0a 1f 1c 06 5a 20 19 01 00 00 2e 23 73 16 00 00 0a 72 30 02 00 70 73 17 00 00 0a 72 c8 01 00 70 6f ?? 00 00 0a 20 40 0d 03 00 28 ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}