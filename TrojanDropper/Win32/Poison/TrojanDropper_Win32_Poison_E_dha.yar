
rule TrojanDropper_Win32_Poison_E_dha{
	meta:
		description = "TrojanDropper:Win32/Poison.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 1f 00 02 00 8d 45 b8 53 50 68 01 00 00 80 ff d7 8b 35 90 01 04 8b f8 ff d6 83 f8 0c 90 00 } //1
		$a_03_1 = {53 50 68 00 40 01 00 68 90 01 04 c6 05 90 01 04 4d ff 75 fc c6 05 90 01 04 5a c6 05 90 01 04 90 90 ff 15 90 01 04 ff d6 83 f8 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}