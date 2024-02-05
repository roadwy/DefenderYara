
rule Trojan_WinNT_Killav_E{
	meta:
		description = "Trojan:WinNT/Killav.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 } //01 00 
		$a_02_1 = {14 20 22 00 0f 84 90 01 04 81 7d 90 01 01 08 20 22 00 0f 84 90 01 04 81 7d 90 01 01 0c 20 22 00 0f 84 90 01 04 81 7d 90 01 01 10 20 22 00 0f 84 90 00 } //01 00 
		$a_02_2 = {20 20 22 00 0f 84 90 01 04 81 7d 90 01 01 24 20 22 00 0f 84 90 01 04 81 7d 90 01 01 57 e1 22 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}