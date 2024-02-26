
rule Trojan_BAT_AsyncRAT_AMMB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 09 02 7b 90 01 01 01 00 04 09 02 7b 90 01 01 01 00 04 8e 69 5d 91 9e 09 17 58 0d 09 20 00 01 00 00 32 e0 90 00 } //05 00 
		$a_01_1 = {11 05 06 11 04 94 58 08 11 04 94 58 20 00 01 00 00 5d 13 05 06 11 04 94 13 06 06 11 04 06 11 05 94 9e 06 11 05 11 06 9e 11 04 17 58 13 04 11 04 20 00 01 00 00 32 c9 } //01 00 
		$a_80_2 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //ProcessHacker.exe  01 00 
		$a_80_3 = {65 78 65 2e 72 65 6b 63 61 48 73 73 65 63 6f 72 50 } //exe.rekcaHssecorP  01 00 
		$a_80_4 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //Select * from AntivirusProduct  01 00 
		$a_80_5 = {74 63 75 64 6f 72 50 73 75 72 69 76 69 74 6e 41 20 6d 6f 72 66 20 2a 20 74 63 65 6c 65 53 } //tcudorPsurivitnA morf * tceleS  00 00 
	condition:
		any of ($a_*)
 
}