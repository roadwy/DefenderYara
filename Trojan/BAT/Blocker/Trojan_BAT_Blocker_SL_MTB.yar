
rule Trojan_BAT_Blocker_SL_MTB{
	meta:
		description = "Trojan:BAT/Blocker.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 09 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 18 58 0b 07 09 6f ?? ?? ?? 0a 32 dd } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}