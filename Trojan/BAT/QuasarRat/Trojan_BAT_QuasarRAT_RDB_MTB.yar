
rule Trojan_BAT_QuasarRAT_RDB_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 35 38 33 38 36 } //1 cc7fad03-816e-432c-9b92-001f2d358386
		$a_01_1 = {73 65 72 76 65 72 31 } //1 server1
		$a_01_2 = {6b 00 6f 00 69 00 } //1 koi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}