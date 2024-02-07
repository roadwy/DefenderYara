
rule Trojan_BAT_AsyncRat_NEAT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 0a 00 00 0a 0a 06 72 01 00 00 70 6f 0b 00 00 0a 06 72 17 00 00 70 6f 0c 00 00 0a 06 17 6f 0d 00 00 0a 06 17 6f 0e 00 00 0a 06 28 0f 00 00 0a 26 2a } //02 00 
		$a_01_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //02 00  powershell
		$a_01_2 = {2d 00 45 00 6e 00 63 00 6f 00 64 00 65 00 64 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //02 00  -EncodedCommand
		$a_01_3 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //00 00  set_CreateNoWindow
	condition:
		any of ($a_*)
 
}