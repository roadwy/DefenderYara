
rule Trojan_BAT_Injuke_PSKX_MTB{
	meta:
		description = "Trojan:BAT/Injuke.PSKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 2b 00 00 70 28 09 00 00 06 13 00 38 00 00 00 00 28 ?? ?? ?? 0a 11 00 6f ?? ?? ?? 0a 72 75 00 00 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 01 38 00 00 00 00 dd 10 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}