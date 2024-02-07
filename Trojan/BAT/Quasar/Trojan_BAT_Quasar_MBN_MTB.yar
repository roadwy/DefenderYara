
rule Trojan_BAT_Quasar_MBN_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0d 08 09 28 90 01 03 06 09 16 6a 6f 90 01 03 0a 09 13 04 de 1c 90 00 } //01 00 
		$a_01_1 = {24 38 63 31 30 32 30 32 35 2d 38 38 31 30 2d 34 30 37 65 2d 39 64 62 37 2d 39 62 31 33 31 62 34 39 39 38 38 30 } //00 00  $8c102025-8810-407e-9db7-9b131b499880
	condition:
		any of ($a_*)
 
}