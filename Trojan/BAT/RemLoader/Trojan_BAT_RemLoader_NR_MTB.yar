
rule Trojan_BAT_RemLoader_NR_MTB{
	meta:
		description = "Trojan:BAT/RemLoader.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 f1 0f 00 0a 6f 53 00 00 0a 07 1f 10 8d 84 00 00 01 25 d0 e0 0b 00 04 28 f1 0f 00 0a 6f 1d 10 00 0a 06 07 6f 55 00 00 0a 17 73 07 10 00 0a 0c 08 02 16 02 8e 69 6f 08 10 00 0a } //5
		$a_01_1 = {24 38 37 37 65 64 61 39 30 2d 39 61 37 39 2d 34 66 61 32 2d 61 38 66 37 2d 32 35 33 37 34 38 63 34 38 39 61 32 } //1 $877eda90-9a79-4fa2-a8f7-253748c489a2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}