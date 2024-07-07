
rule Backdoor_Linux_Tsunami_D_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 61 63 6b 6d 65 70 6c 73 } //1 hackmepls
		$a_02_1 = {48 54 54 50 20 46 6c 6f 6f 64 69 6e 67 20 90 02 04 2f 2f 25 73 3a 25 73 25 73 90 00 } //1
		$a_00_2 = {57 74 66 20 69 73 20 74 68 69 73 20 73 68 69 74 3a 20 25 73 } //1 Wtf is this shit: %s
		$a_00_3 = {53 54 44 20 46 6c 6f 6f 64 69 6e 67 } //1 STD Flooding
		$a_00_4 = {52 41 57 55 44 50 20 46 6c 6f 6f 64 69 6e 67 } //1 RAWUDP Flooding
		$a_00_5 = {6d 61 6a 65 73 74 69 63 31 32 2e 63 6f 2e 75 6b 2f 62 6f 74 2e 70 68 70 3f } //1 majestic12.co.uk/bot.php?
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}