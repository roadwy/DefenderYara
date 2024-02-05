
rule Trojan_BAT_AsyncRAT_ARA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //Select * from AntivirusProduct  02 00 
		$a_80_1 = {56 65 6e 6f 6d 42 79 56 65 6e 6f 6d } //VenomByVenom  02 00 
		$a_80_2 = {50 61 73 74 65 5f 62 69 6e } //Paste_bin  02 00 
		$a_80_3 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 74 6e } ///c schtasks /create /f /sc onlogon /rl highest /tn  02 00 
		$a_80_4 = {6d 61 73 74 65 72 4b 65 79 20 63 61 6e 20 6e 6f 74 20 62 65 20 6e 75 6c 6c 20 6f 72 20 65 6d 70 74 79 2e } //masterKey can not be null or empty.  00 00 
	condition:
		any of ($a_*)
 
}