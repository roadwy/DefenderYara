
rule Trojan_BAT_Bladabindi_AW_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_00_0 = {01 57 15 a2 09 09 01 00 00 00 00 00 00 00 00 00 00 01 00 00 00 2f } //03 00 
		$a_01_1 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 2e 54 61 73 6b 73 } //03 00  System.Threading.Tasks
		$a_01_2 = {53 79 73 74 65 6d 2e 4e 65 74 2e 48 74 74 70 } //03 00  System.Net.Http
		$a_01_3 = {50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f } //03 00  ProcessStartInfo
		$a_01_4 = {48 74 74 70 43 6c 69 65 6e 74 } //00 00  HttpClient
	condition:
		any of ($a_*)
 
}