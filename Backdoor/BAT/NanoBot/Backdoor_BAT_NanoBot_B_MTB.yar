
rule Backdoor_BAT_NanoBot_B_MTB{
	meta:
		description = "Backdoor:BAT/NanoBot.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 00 02 28 90 01 04 72 90 01 04 28 90 01 04 0a 28 90 01 04 06 6f 90 01 04 0b 07 6f 90 01 04 17 9a 0c 02 08 28 90 01 04 00 28 90 01 04 00 16 0d 2b 00 09 90 00 } //01 00 
		$a_00_1 = {67 65 74 5f 45 6e 63 72 79 70 74 65 64 32 } //01 00  get_Encrypted2
		$a_00_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_00_3 = {59 00 6f 00 64 00 61 00 2d 00 43 00 6f 00 66 00 66 00 65 00 65 00 33 00 } //00 00  Yoda-Coffee3
	condition:
		any of ($a_*)
 
}