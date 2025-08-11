
rule Trojan_BAT_Zusy_NU_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 72 ?? 00 00 70 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 26 } //3
		$a_01_1 = {24 36 65 66 39 62 31 65 35 2d 33 30 64 34 2d 34 31 31 32 2d 62 61 39 37 2d 65 65 62 63 35 66 38 61 63 35 64 38 } //1 $6ef9b1e5-30d4-4112-ba97-eebc5f8ac5d8
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}