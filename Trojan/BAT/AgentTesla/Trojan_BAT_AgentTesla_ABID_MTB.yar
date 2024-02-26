
rule Trojan_BAT_AgentTesla_ABID_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {4b 00 68 00 61 00 6f 00 73 00 42 00 72 00 69 00 6e 00 67 00 68 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //02 00  KhaosBringher.Properties.Resources
		$a_01_1 = {4b 00 68 00 61 00 6f 00 73 00 4b 00 69 00 73 00 73 00 4d 00 65 00 } //02 00  KhaosKissMe
		$a_01_2 = {4b 00 68 00 61 00 6f 00 73 00 42 00 72 00 69 00 6e 00 67 00 68 00 65 00 72 00 4b 00 68 00 61 00 6f 00 73 00 42 00 72 00 69 00 6e 00 67 00 68 00 65 00 72 00 } //02 00  KhaosBringherKhaosBringher
		$a_01_3 = {4b 00 68 00 61 00 6f 00 73 00 42 00 72 00 69 00 6e 00 67 00 68 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  KhaosBringher.exe
	condition:
		any of ($a_*)
 
}