
rule Trojan_BAT_SnakeKeylogger_SHPF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SHPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 73 22 00 00 0a 0d 09 08 17 73 23 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 13 05 dd 29 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}