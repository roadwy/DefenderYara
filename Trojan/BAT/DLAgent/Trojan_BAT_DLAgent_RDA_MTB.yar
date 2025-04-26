
rule Trojan_BAT_DLAgent_RDA_MTB{
	meta:
		description = "Trojan:BAT/DLAgent.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 16 00 00 0a 25 07 6f 17 00 00 0a 6f 18 00 00 0a 26 } //2
		$a_01_1 = {57 33 32 54 69 6d 65 } //1 W32Time
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}