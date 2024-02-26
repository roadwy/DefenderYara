
rule Trojan_BAT_Mimpe_RS_MTB{
	meta:
		description = "Trojan:BAT/Mimpe.RS!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 5f 00 72 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 76 00 65 00 5f 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //01 00  powershell_reflective_mimikatz
		$a_01_1 = {67 65 74 5f 4d 69 6d 69 6b 61 74 7a 50 45 } //01 00  get_MimikatzPE
		$a_01_2 = {73 65 74 5f 4d 69 6d 69 6b 61 74 7a 50 45 } //00 00  set_MimikatzPE
	condition:
		any of ($a_*)
 
}