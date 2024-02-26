
rule Trojan_Win64_StrelaStealer_ASDE_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 41 57 41 56 41 55 41 54 56 57 53 48 81 ec 90 02 03 00 48 8d ac 24 80 00 00 00 e8 90 02 03 00 c7 85 90 02 03 00 00 00 00 00 c7 85 90 02 03 00 00 00 00 00 31 c0 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}