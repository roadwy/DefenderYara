
rule Trojan_BAT_Xmrig_AHRL_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.AHRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 0d 9a 6f ?? ?? ?? 0a 11 05 11 0e 9a 28 ?? ?? ?? 0a 13 0f 11 0f 2c 11 00 28 ?? ?? ?? 0a 13 10 11 10 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}