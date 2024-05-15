
rule Trojan_BAT_Lokibot_SG_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.SG!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {24 63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 35 38 38 38 39 } //01 00  $cc7fad03-816e-432c-9b92-001f2d358889
		$a_01_1 = {46 61 69 6c 46 61 73 74 } //01 00  FailFast
		$a_01_2 = {56 48 44 20 49 6d 61 67 65 } //03 00  VHD Image
		$a_01_3 = {24 63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 35 38 36 39 39 } //00 00  $cc7fad03-816e-432c-9b92-001f2d358699
	condition:
		any of ($a_*)
 
}