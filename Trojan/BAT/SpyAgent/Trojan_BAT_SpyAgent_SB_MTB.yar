
rule Trojan_BAT_SpyAgent_SB_MTB{
	meta:
		description = "Trojan:BAT/SpyAgent.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 6f 4e 00 00 0a 72 db 07 00 70 28 3b 00 00 0a 2c 64 07 08 9a 6f 50 00 00 0a 0d 09 28 ?? ?? ?? 0a 72 5b 08 00 70 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}