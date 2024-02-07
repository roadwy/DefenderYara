
rule Trojan_BAT_Xmrig_NEA_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 66 35 35 34 65 65 62 62 2d 36 35 62 64 2d 34 66 62 65 2d 61 39 31 32 2d 38 33 62 34 63 31 30 61 65 35 34 64 } //01 00  $f554eebb-65bd-4fbe-a912-83b4c10ae54d
		$a_01_1 = {6d 40 41 40 43 4d 44 } //01 00  m@A@CMD
		$a_01_2 = {77 4b 68 4b 5b 59 59 4f 57 5d 53 54 } //01 00  wKhK[YYOW]ST
		$a_01_3 = {43 31 39 30 38 33 33 38 36 38 31 } //01 00  C1908338681
		$a_01_4 = {43 00 41 00 44 00 31 00 30 00 39 00 34 00 33 00 38 00 38 00 38 00 37 00 35 00 } //00 00  CAD1094388875
	condition:
		any of ($a_*)
 
}