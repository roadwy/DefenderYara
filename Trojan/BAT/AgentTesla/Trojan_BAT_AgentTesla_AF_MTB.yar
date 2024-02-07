
rule Trojan_BAT_AgentTesla_AF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {95 2e 03 17 2b 01 16 58 7e 2a 00 00 04 7e 10 00 00 04 20 0d 07 00 00 95 e0 95 7e 10 00 00 04 20 de 0f 00 00 95 61 7e 10 00 00 04 20 fa 0c 00 00 95 2e 03 17 2b 01 16 } //02 00 
		$a_01_1 = {20 c5 0d 00 00 95 e0 95 7e 10 00 00 04 20 8e 11 00 00 95 61 7e 10 00 00 04 20 b4 0e 00 00 95 2e 03 17 2b 01 16 58 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AF!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 73 00 5c 00 48 00 6f 00 74 00 65 00 6c 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 6d 00 5c 00 48 00 6f 00 74 00 65 00 6c 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 6d 00 5c 00 48 00 6f 00 74 00 65 00 6c 00 2e 00 6d 00 64 00 66 00 } //01 00  Projects\HotelManagementSystemRoom\HotelManagementSystemRoom\Hotel.mdf
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 6d 00 70 00 75 00 72 00 69 00 2e 00 6f 00 72 00 67 00 2f 00 48 00 6f 00 74 00 65 00 6c 00 44 00 61 00 74 00 61 00 53 00 65 00 74 00 2e 00 78 00 73 00 64 00 } //01 00  http://tempuri.org/HotelDataSet.xsd
		$a_01_2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 20 00 46 00 52 00 4f 00 4d 00 20 00 61 00 64 00 6d 00 69 00 6e 00 20 00 57 00 48 00 45 00 52 00 45 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 } //00 00  SELECT username FROM admin WHERE password=
	condition:
		any of ($a_*)
 
}