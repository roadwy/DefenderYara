
rule Trojan_BAT_Disstl_CA_MTB{
	meta:
		description = "Trojan:BAT/Disstl.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0d 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {32 42 3e 11 04 28 90 01 03 06 17 8d 90 01 03 01 13 06 11 06 16 1f 22 9d 11 06 6f 90 01 03 0a 13 05 11 05 16 9a 0d 72 90 01 03 70 11 05 28 90 01 03 0a 13 04 03 2c 0a 09 6f 90 01 03 0a 1f 3b 90 00 } //05 00 
		$a_80_1 = {5c 64 69 73 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 5c } //\discord\Local Storage\leveldb\  04 00 
		$a_80_2 = {44 69 73 63 6f 72 64 54 6f 6b 65 6e } //DiscordToken  03 00 
		$a_80_3 = {52 65 61 64 4c 6f 67 46 69 6c 65 } //ReadLogFile  03 00 
		$a_80_4 = {5c 4c 6f 67 43 6f 70 79 2e 74 78 74 } //\LogCopy.txt  03 00 
		$a_80_5 = {53 6f 66 74 77 61 72 65 5c 47 72 6f 77 74 6f 70 69 61 } //Software\Growtopia  00 00 
	condition:
		any of ($a_*)
 
}