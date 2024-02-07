
rule Trojan_Win32_Tinba_DSK_MTB{
	meta:
		description = "Trojan:Win32/Tinba.DSK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 37 79 48 61 61 4f 67 6e 79 32 54 4d 53 } //01 00  D7yHaaOgny2TMS
		$a_01_1 = {73 72 42 53 4c 41 47 6f 46 70 } //01 00  srBSLAGoFp
		$a_01_2 = {30 32 45 35 59 59 4b 6d } //02 00  02E5YYKm
		$a_01_3 = {8b 85 50 ff ff ff 05 01 00 00 00 66 8b 4d de 66 81 f1 ea 06 66 89 4d de 89 85 50 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}