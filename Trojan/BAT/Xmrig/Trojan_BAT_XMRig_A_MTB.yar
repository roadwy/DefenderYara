
rule Trojan_BAT_XMRig_A_MTB{
	meta:
		description = "Trojan:BAT/XMRig.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {58 4d 52 5f 47 4f } //02 00  XMR_GO
		$a_01_1 = {50 4f 4f 4c 5f 58 4d 52 } //02 00  POOL_XMR
		$a_01_2 = {55 52 4c 50 41 4e 45 4c } //01 00  URLPANEL
		$a_01_3 = {49 73 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //01 00  IsAdministrator
		$a_01_4 = {4d 61 6e 61 67 65 6d 65 6e 74 4f 62 6a 65 63 74 53 65 61 72 63 68 65 72 } //00 00  ManagementObjectSearcher
	condition:
		any of ($a_*)
 
}