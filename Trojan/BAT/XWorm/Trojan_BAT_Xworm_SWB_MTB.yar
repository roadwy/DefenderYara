
rule Trojan_BAT_Xworm_SWB_MTB{
	meta:
		description = "Trojan:BAT/Xworm.SWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d0 49 00 00 01 28 ?? 00 00 0a 72 da 01 00 70 18 8d 1f 00 00 01 25 16 d0 17 00 00 01 28 ?? 00 00 0a a2 25 17 d0 1f 00 00 01 28 ?? 00 00 0a a2 28 ?? 00 00 0a 14 18 8d 07 00 00 01 25 16 02 8c 17 00 00 01 a2 25 17 03 a2 6f ?? 00 00 0a 74 42 00 00 01 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}