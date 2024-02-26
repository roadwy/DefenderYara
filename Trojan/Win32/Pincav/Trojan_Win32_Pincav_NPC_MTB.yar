
rule Trojan_Win32_Pincav_NPC_MTB{
	meta:
		description = "Trojan:Win32/Pincav.NPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8d 94 24 ca 01 00 00 83 c4 0c 8d 8c 24 90 01 04 8a 84 24 bc 01 00 00 30 42 90 01 01 42 39 ca 75 f1 90 00 } //01 00 
		$a_01_1 = {44 65 6c 65 74 65 46 69 6c 65 41 } //00 00  DeleteFileA
	condition:
		any of ($a_*)
 
}