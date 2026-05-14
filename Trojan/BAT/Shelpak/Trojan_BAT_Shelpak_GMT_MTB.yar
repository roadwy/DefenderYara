
rule Trojan_BAT_Shelpak_GMT_MTB{
	meta:
		description = "Trojan:BAT/Shelpak.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 18 5a 58 0a 06 08 59 0a 06 08 61 0a 08 17 58 0c 08 7e ?? 00 00 04 1f 0a 1f 64 6f ?? 00 00 0a 32 dd } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}