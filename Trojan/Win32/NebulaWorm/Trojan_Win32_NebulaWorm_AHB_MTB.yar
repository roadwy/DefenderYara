
rule Trojan_Win32_NebulaWorm_AHB_MTB{
	meta:
		description = "Trojan:Win32/NebulaWorm.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 02 03 6f b8 00 00 0a 04 6f b9 00 00 0a 2c 08 06 6f ba 00 00 0a 2b 01 16 0b de 0f } //3
		$a_03_1 = {0a 18 33 56 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 11 04 72 be 15 00 70 28 2b 00 00 0a 13 05 11 05 28 24 00 00 0a 2d 10 06 11 05 28 c3 00 00 0a 11 05 1c 28 c4 00 00 0a 11 04 72 da 15 00 70 28 2b 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}