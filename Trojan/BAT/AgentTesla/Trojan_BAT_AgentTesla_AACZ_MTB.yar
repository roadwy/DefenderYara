
rule Trojan_BAT_AgentTesla_AACZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AACZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {04 16 06 7b 90 01 01 00 00 04 6f 90 01 01 01 00 0a 28 90 01 01 01 00 0a 7e 90 01 01 00 00 04 25 2d 17 26 7e 90 01 01 00 00 04 fe 90 01 02 00 00 06 73 90 01 01 01 00 0a 25 80 90 01 01 00 00 04 28 90 01 01 00 00 2b 06 fe 90 01 02 00 00 06 73 90 01 01 01 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0c 90 00 } //01 00 
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 69 00 44 00 6f 00 61 00 6e 00 56 00 69 00 65 00 6e 00 } //00 00  QuanLiDoanVien
	condition:
		any of ($a_*)
 
}