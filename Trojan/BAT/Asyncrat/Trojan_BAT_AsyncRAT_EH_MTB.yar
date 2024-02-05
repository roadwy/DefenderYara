
rule Trojan_BAT_AsyncRAT_EH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {09 09 1f 0c 64 61 0d 09 09 1f 19 62 61 0d 09 09 1f 1b 64 61 0d 08 11 04 09 9e 11 04 17 58 13 04 11 04 1f 10 32 da } //01 00 
		$a_01_1 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 16 00 00 00 55 } //00 00 
	condition:
		any of ($a_*)
 
}