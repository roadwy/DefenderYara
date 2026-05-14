
rule Trojan_BAT_AsyncRAT_SJ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {28 15 00 00 0a 11 00 6f 16 00 00 0a 2a 28 1e 00 00 06 28 0d 00 00 06 28 0a 00 00 06 13 00 38 dd ff ff ff } //1
		$a_02_1 = {28 1b 00 00 06 72 [0-02] 00 00 70 7e 0b 00 00 04 6f 20 00 00 0a 74 01 00 00 1b 2a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}