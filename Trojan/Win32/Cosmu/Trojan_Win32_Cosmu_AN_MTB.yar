
rule Trojan_Win32_Cosmu_AN_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 50 ff d7 00 5d fb 33 1c 70 00 6c 70 ff 1b d8 00 2a 31 70 ff 1e f7 01 04 e0 fe 3a } //01 00 
		$a_01_1 = {6c 45 78 65 63 75 74 65 45 78 00 00 18 35 40 00 28 35 40 00 00 00 04 00 78 } //00 00 
	condition:
		any of ($a_*)
 
}