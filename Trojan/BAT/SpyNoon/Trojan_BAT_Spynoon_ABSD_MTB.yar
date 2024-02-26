
rule Trojan_BAT_Spynoon_ABSD_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ABSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {4a 68 48 68 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  JhHh.Resources.resources
		$a_01_1 = {24 62 63 63 34 31 36 36 35 2d 34 39 32 63 2d 34 34 65 35 2d 39 62 37 63 2d 33 34 64 30 66 32 63 62 31 38 36 36 } //00 00  $bcc41665-492c-44e5-9b7c-34d0f2cb1866
	condition:
		any of ($a_*)
 
}