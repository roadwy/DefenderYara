
rule Trojan_BAT_Stimilini_H{
	meta:
		description = "Trojan:BAT/Stimilini.H,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 09 00 "
		
	strings :
		$a_80_0 = {00 53 74 65 61 6d 53 74 65 61 6c 65 72 45 78 74 72 65 6d 65 } //  01 00 
		$a_00_1 = {00 73 74 65 61 6d 43 6f 6f 6b 69 65 73 00 } //01 00  猀整浡潃歯敩s
		$a_00_2 = {00 53 74 65 61 6d 50 72 6f 66 69 6c 65 00 } //01 00  匀整浡牐景汩e
		$a_00_3 = {00 47 65 74 53 74 65 61 6d 49 74 65 6d 73 00 } //01 00 
		$a_00_4 = {00 53 74 65 61 6d 57 65 62 52 65 71 75 65 73 74 00 } //01 00 
		$a_00_5 = {00 6d 5f 44 65 63 6f 64 65 72 73 00 } //00 00  洀䑟捥摯牥s
		$a_00_6 = {5d 04 00 00 6d 2b 03 80 5c } //31 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Stimilini_H_2{
	meta:
		description = "Trojan:BAT/Stimilini.H,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6d 53 74 65 61 6c 65 72 45 78 74 72 65 6d 65 } //01 00  SteamStealerExtreme
		$a_01_1 = {2e 49 74 65 6d 3e 3e 2e 47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } //01 00  .Item>>.GetEnumerator
		$a_01_2 = {2e 49 74 65 6d 3e 3e 2e 67 65 74 5f 43 75 72 72 65 6e 74 } //00 00  .Item>>.get_Current
		$a_01_3 = {00 67 16 00 00 } //c7 cf 
	condition:
		any of ($a_*)
 
}