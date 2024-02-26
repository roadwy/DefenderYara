
rule Trojan_Win64_StrelaStealer_ASDD_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 41 57 41 56 41 55 41 54 56 57 53 48 81 ec 90 01 03 00 48 8d ac 24 80 00 00 00 48 83 ec 20 e8 90 01 03 00 48 83 c4 20 90 00 } //05 00 
		$a_03_1 = {55 41 57 41 56 41 55 41 54 56 57 53 48 81 ec 90 01 03 00 48 8d ac 24 80 00 00 00 e8 90 01 03 00 c7 85 90 01 03 00 00 00 00 00 c7 85 90 01 03 00 00 00 00 00 81 bd 90 01 03 00 cc 0c 00 00 0f 90 01 03 00 00 31 c0 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}