
rule Trojan_BAT_NjRAT_PSQQ_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PSQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 3f 00 00 0a 74 09 00 00 01 80 0b 00 00 04 1b 39 d4 ff ff ff 11 05 74 38 00 00 01 28 40 00 00 0a 74 34 00 00 01 0a dd 68 00 00 00 73 41 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}