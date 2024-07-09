
rule Trojan_BAT_AgentTesla_CKE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 06 02 28 ?? ?? ?? ?? 06 02 28 ?? ?? ?? ?? 8e 69 5d 91 03 06 91 61 d2 9c 06 17 58 0a 06 03 8e 69 17 59 fe [0-02] 16 fe [0-02] 0b 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}