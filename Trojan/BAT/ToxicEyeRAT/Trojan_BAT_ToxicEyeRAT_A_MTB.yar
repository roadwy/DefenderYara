
rule Trojan_BAT_ToxicEyeRAT_A_MTB{
	meta:
		description = "Trojan:BAT/ToxicEyeRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 65 6c 65 67 72 61 6d 52 41 54 } //02 00  TelegramRAT
		$a_01_1 = {31 62 63 66 65 35 33 38 2d 31 34 66 34 2d 34 62 65 62 2d 39 61 33 66 2d 33 66 39 34 37 32 37 39 34 39 30 32 } //01 00  1bcfe538-14f4-4beb-9a3f-3f9472794902
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_3 = {45 6e 75 6d 44 69 73 70 6c 61 79 44 65 76 69 63 65 73 } //01 00  EnumDisplayDevices
		$a_01_4 = {47 61 74 65 77 61 79 49 50 41 64 64 72 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e } //00 00  GatewayIPAddressInformation
	condition:
		any of ($a_*)
 
}