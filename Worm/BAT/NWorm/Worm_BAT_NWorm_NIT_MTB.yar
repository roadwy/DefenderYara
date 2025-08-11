
rule Worm_BAT_NWorm_NIT_MTB{
	meta:
		description = "Worm:BAT/NWorm.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 0a 73 1d 00 00 0a 0b 07 28 1e 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 07 6f ?? 00 00 0a 73 22 00 00 0a 0c 08 06 6f ?? 00 00 0a 08 04 6f ?? 00 00 0a 08 05 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 13 04 08 6f ?? 00 00 0a 11 04 2a } //2
		$a_03_1 = {28 18 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=3
 
}