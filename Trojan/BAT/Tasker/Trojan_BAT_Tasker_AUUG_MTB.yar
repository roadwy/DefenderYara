
rule Trojan_BAT_Tasker_AUUG_MTB{
	meta:
		description = "Trojan:BAT/Tasker.AUUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 1a 8d ?? ?? ?? 01 0b 03 15 16 6f ?? ?? ?? 0a 26 03 07 16 1a 16 6f ?? ?? ?? 0a 0c 07 16 28 ?? ?? ?? 0a 0d 09 13 04 09 8d ?? ?? ?? 01 13 05 2b 17 03 11 05 06 11 04 16 6f ?? ?? ?? 0a 0c 06 08 58 0a 11 04 08 59 13 04 06 09 32 e5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}