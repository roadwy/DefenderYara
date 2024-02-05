
rule TrojanSpy_BAT_Quasar_SL_MTB{
	meta:
		description = "TrojanSpy:BAT/Quasar.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 31 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_1 = {43 6c 6c 69 6b 69 6f 6d 20 4b 66 73 64 67 67 69 6d 6f 20 4d 65 64 69 61 } //01 00 
		$a_01_2 = {73 65 72 76 65 72 31 2e 65 78 65 } //01 00 
		$a_01_3 = {32 30 32 31 20 43 6c 6c 69 6b 69 6f 6d 20 4b 66 73 64 67 67 69 6d 6f } //00 00 
	condition:
		any of ($a_*)
 
}