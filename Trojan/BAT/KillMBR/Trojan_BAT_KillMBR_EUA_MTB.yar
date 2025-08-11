
rule Trojan_BAT_KillMBR_EUA_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.EUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {58 08 09 07 16 1f ec 11 05 58 20 84 75 98 00 ?? ?? ?? ?? ?? 26 07 16 1f ec 11 05 58 08 09 07 16 1f 14 11 04 58 20 84 75 98 00 ?? ?? ?? ?? ?? 26 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}