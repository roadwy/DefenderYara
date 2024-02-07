
rule Trojan_BAT_RedLine_RDBO_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 38 64 31 62 34 66 61 2d 32 61 66 62 2d 34 64 35 66 2d 62 37 31 65 2d 39 35 66 33 33 64 32 30 39 65 62 36 } //01 00  d8d1b4fa-2afb-4d5f-b71e-95f33d209eb6
		$a_01_1 = {44 64 6d 68 78 66 75 } //01 00  Ddmhxfu
		$a_01_2 = {2f 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 73 00 68 00 2f 00 67 00 65 00 74 00 2f 00 48 00 4c 00 43 00 30 00 74 00 38 00 2f 00 50 00 68 00 79 00 65 00 6d 00 72 00 66 00 6a 00 2e 00 70 00 6e 00 67 00 } //01 00  //transfer.sh/get/HLC0t8/Phyemrfj.png
		$a_01_3 = {45 00 63 00 6f 00 6f 00 67 00 6c 00 72 00 61 00 63 00 63 00 72 00 67 00 68 00 72 00 71 00 64 00 72 00 61 00 } //00 00  Ecooglraccrghrqdra
	condition:
		any of ($a_*)
 
}