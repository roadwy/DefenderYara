
rule Trojan_BAT_AsyncRAT_BGJ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 0b ?? ?? 00 00 0a 17 73 0e 00 00 0a 13 04 38 00 00 00 00 00 11 04 02 16 02 8e 69 ?? ?? 00 00 0a 38 2e 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 0a 00 fe 0c 0a 00 45 01 00 00 00 47 00 00 00 fe 0c 0a 00 20 dc 03 00 00 3b e5 ff ff ff 38 34 00 00 00 11 04 ?? ?? 00 00 0a 38 00 00 00 00 11 08 ?? ?? 00 00 0a 13 07 20 00 00 00 00 7e 30 00 00 04 7b 0d 00 00 04 3a bb ff ff ff 26 20 01 00 00 00 38 b0 ff ff ff dd 07 02 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}