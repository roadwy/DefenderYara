
rule Trojan_BAT_AsyncRat_BA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 16 0c 2b 20 08 02 07 02 8e 69 5d 91 58 06 07 91 58 20 ff 00 00 00 5f 0c 06 07 08 28 09 00 00 06 07 17 58 0b 07 20 00 01 00 00 32 d8 06 2a } //01 00 
		$a_01_1 = {43 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //02 00  Crypted.exe
		$a_01_2 = {72 01 00 00 70 6f 0b 00 00 0a 06 72 17 00 00 70 6f 0c 00 00 0a 06 17 6f 0d 00 00 0a 06 17 6f 0e 00 00 0a 06 28 0f 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}