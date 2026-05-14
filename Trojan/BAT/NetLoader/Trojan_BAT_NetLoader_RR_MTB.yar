
rule Trojan_BAT_NetLoader_RR_MTB{
	meta:
		description = "Trojan:BAT/NetLoader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 12 a2 11 21 1a 72 f2 [0-02] 70 a2 11 21 1b 28 28 [0-02] 0a 6f 29 00 00 0a a2 11 21 1c 72 0c [0-02] 70 a2 11 21 1d 11 0c a2 11 21 1e 72 [0-02] 00 70 a2 11 21 28 [0-02] 00 0a 6f [0-02] 00 0a 26 2b 0a 11 05 11 12 6f 07 01 00 0a 26 de 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}