
rule Trojan_Win64_VaporRage_N_dha{
	meta:
		description = "Trojan:Win64/VaporRage.N!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_43_0 = {83 ec 28 ff ca 75 90 01 01 b9 90 01 01 00 00 00 e8 90 01 02 ff ff 48 8d 0d 90 01 02 ff ff 3d 90 01 04 74 90 14 e8 90 01 02 ff ff b8 01 00 00 00 48 83 c4 28 c3 90 00 00 } //00 5d 
	condition:
		any of ($a_*)
 
}