
rule Trojan_Win64_Meterpreter_I_attk{
	meta:
		description = "Trojan:Win64/Meterpreter.I!attk,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 30 48 89 4d 10 48 8b 45 10 48 89 45 f8 48 8b 45 f8 ff d0 90 48 83 c4 30 5d c3 } //01 00 
		$a_01_1 = {00 25 63 25 63 00 } //01 00  ─╣c
		$a_01_2 = {6c 69 62 67 63 6a 2d 31 36 2e 64 6c 6c 00 5f 4a 76 5f 52 65 67 69 73 74 65 72 43 6c 61 73 73 65 73 } //01 00 
		$a_01_3 = {00 65 78 65 63 5f 73 68 65 6c 6c 63 6f 64 65 00 } //00 00  攀數彣桳汥捬摯e
	condition:
		any of ($a_*)
 
}