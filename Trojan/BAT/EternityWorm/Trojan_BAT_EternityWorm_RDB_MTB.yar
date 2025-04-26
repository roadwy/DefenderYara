
rule Trojan_BAT_EternityWorm_RDB_MTB{
	meta:
		description = "Trojan:BAT/EternityWorm.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 0c 00 1f 15 62 fe 0c 14 00 59 fe 0c 0c 00 61 fe 0c 16 00 59 } //2
		$a_01_1 = {65 65 62 64 35 30 66 34 2d 38 63 64 63 2d 34 61 62 61 2d 38 66 66 65 2d 64 62 31 37 32 32 64 37 36 61 65 64 } //1 eebd50f4-8cdc-4aba-8ffe-db1722d76aed
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}