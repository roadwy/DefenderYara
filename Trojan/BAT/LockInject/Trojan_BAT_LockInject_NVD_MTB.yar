
rule Trojan_BAT_LockInject_NVD_MTB{
	meta:
		description = "Trojan:BAT/LockInject.NVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 b7 00 00 70 a2 25 17 72 bb 00 00 70 a2 25 18 72 bf 00 00 70 a2 25 19 72 c3 00 00 70 a2 25 1a 72 bb 00 00 70 a2 25 1b 72 c7 00 00 70 a2 25 1c } //01 00 
		$a_01_1 = {72 cb 00 00 70 a2 25 1d 72 cf 00 00 70 a2 25 1e 72 d3 00 00 70 a2 25 1f 09 72 d7 00 00 70 a2 25 1f 0a 72 db 00 00 70 a2 25 1f 0b 72 db 00 00 70 } //01 00 
		$a_01_2 = {37 32 66 30 36 66 62 65 39 30 63 38 } //01 00 
		$a_01_3 = {6b 69 64 4c 6f 63 6b 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}