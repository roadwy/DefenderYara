
rule Trojan_BAT_StormKitty_MBT_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.MBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 06 } //1
		$a_01_1 = {41 00 66 00 7a 00 64 00 49 00 48 00 4f 00 66 00 47 00 69 00 37 00 33 00 32 00 33 00 53 00 66 00 } //1 AfzdIHOfGi7323Sf
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}