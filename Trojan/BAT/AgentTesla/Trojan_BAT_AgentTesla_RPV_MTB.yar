
rule Trojan_BAT_AgentTesla_RPV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  cdn.discordapp.com
		$a_01_1 = {61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 } //01 00  attachments
		$a_01_2 = {4a 00 61 00 6d 00 63 00 6b 00 79 00 62 00 66 00 2e 00 62 00 6d 00 70 00 } //01 00  Jamckybf.bmp
		$a_01_3 = {58 00 6c 00 6f 00 74 00 78 00 66 00 6f 00 73 00 72 00 7a 00 6b 00 6f 00 7a 00 79 00 } //01 00  Xlotxfosrzkozy
		$a_01_4 = {66 00 6f 00 72 00 75 00 6d 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  forums.txt
		$a_01_5 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_01_6 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_7 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 00 65 00 74 00 42 00 79 00 74 00 65 00 41 00 72 00 72 00 61 00 79 00 41 00 73 00 79 00 6e 00 63 00 } //01 00  GetByteArrayAsync
		$a_01_1 = {31 00 38 00 35 00 2e 00 32 00 32 00 32 00 2e 00 35 00 38 00 2e 00 35 00 36 00 } //01 00  185.222.58.56
		$a_01_2 = {45 00 64 00 6b 00 70 00 6a 00 76 00 2e 00 6a 00 70 00 67 00 } //01 00  Edkpjv.jpg
		$a_01_3 = {50 00 76 00 7a 00 70 00 64 00 66 00 68 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  Pvzpdfh.Properties.Resources
		$a_01_4 = {52 00 6d 00 6a 00 74 00 6e 00 7a 00 67 00 71 00 62 00 7a 00 71 00 67 00 78 00 6d 00 6a 00 6e 00 72 00 68 00 6b 00 70 00 64 00 62 00 68 00 6a 00 } //00 00  Rmjtnzgqbzqgxmjnrhkpdbhj
	condition:
		any of ($a_*)
 
}