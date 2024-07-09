
rule Trojan_BAT_Tasker_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Tasker.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 08 6f ?? ?? 00 0a 1f 20 08 6f ?? ?? 00 0a 8e 69 1f 20 59 6f ?? ?? 00 0a 0a 1f 20 8d ?? ?? ?? 01 0b 08 07 16 07 8e 69 6f ?? ?? ?? 0a 26 02 06 07 0a 0b 26 17 13 07 16 } //5
		$a_03_1 = {0a 08 25 06 16 1f 10 6f ?? 00 00 0a 26 09 25 06 6f ?? 00 00 0a 6f } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}