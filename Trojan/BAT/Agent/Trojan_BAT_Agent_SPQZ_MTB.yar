
rule Trojan_BAT_Agent_SPQZ_MTB{
	meta:
		description = "Trojan:BAT/Agent.SPQZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 72 17 00 00 70 28 14 00 00 0a 26 20 d0 07 00 00 28 22 00 00 0a 00 72 01 00 00 70 72 b8 00 00 70 28 14 00 00 0a 26 20 b8 0b 00 00 28 22 00 00 0a 00 72 01 00 00 70 72 65 02 00 70 28 14 00 00 0a 26 2a } //2
		$a_01_1 = {6e 64 69 72 6d 65 44 65 6e 65 6d 65 6c 65 72 69 2e 70 64 62 } //1 ndirmeDenemeleri.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}