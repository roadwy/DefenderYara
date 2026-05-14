
rule Trojan_Win64_PurgeLogger_GVB_MTB{
	meta:
		description = "Trojan:Win64/PurgeLogger.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 08 00 00 06 28 02 00 00 0a 6f 03 00 00 0a 13 03 38 b6 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 00 00 fe 0c 00 00 } //2
		$a_01_1 = {28 13 00 00 06 7e 04 00 00 04 7e 05 00 00 04 28 09 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}