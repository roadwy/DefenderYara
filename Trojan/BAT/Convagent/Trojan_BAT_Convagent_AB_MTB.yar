
rule Trojan_BAT_Convagent_AB_MTB{
	meta:
		description = "Trojan:BAT/Convagent.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 20 a0 8e cd e8 58 0d 09 20 b2 4f 09 d2 59 16 16 61 61 16 62 2b b1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}