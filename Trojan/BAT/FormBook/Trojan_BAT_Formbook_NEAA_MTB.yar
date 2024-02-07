
rule Trojan_BAT_Formbook_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {24 62 38 39 65 34 30 38 63 2d 36 38 36 35 2d 34 38 30 30 2d 38 36 38 38 2d 30 32 37 66 39 63 66 34 63 61 64 62 } //05 00  $b89e408c-6865-4800-8688-027f9cf4cadb
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 } //05 00  aR3nbf8dQp2feLmk31
		$a_01_2 = {75 6d 4c 6f 63 65 68 75 45 43 } //05 00  umLocehuEC
		$a_01_3 = {4b 44 69 6b 4d 58 65 77 43 49 } //02 00  KDikMXewCI
		$a_01_4 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 33 39 35 2d 31 } //00 00  $$method0x6000395-1
	condition:
		any of ($a_*)
 
}