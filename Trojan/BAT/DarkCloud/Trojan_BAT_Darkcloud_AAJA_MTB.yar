
rule Trojan_BAT_Darkcloud_AAJA_MTB{
	meta:
		description = "Trojan:BAT/Darkcloud.AAJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 0f 01 20 47 03 00 00 20 30 03 00 00 28 ?? 00 00 06 9c 25 17 0f 01 20 f1 00 00 00 20 89 00 00 00 28 ?? 00 00 06 9c 25 18 0f 01 20 39 01 00 00 20 40 01 00 00 28 ?? 00 00 06 9c 6f ?? 00 00 0a 16 0d } //3
		$a_03_1 = {01 25 16 0f 00 20 4a 01 00 00 20 3d 01 00 00 28 ?? 00 00 06 9c 25 17 0f 00 20 8c 03 00 00 20 f4 03 00 00 28 ?? 00 00 06 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 17 0c 2b 8f } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}