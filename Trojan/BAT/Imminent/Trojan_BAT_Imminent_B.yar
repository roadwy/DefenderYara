
rule Trojan_BAT_Imminent_B{
	meta:
		description = "Trojan:BAT/Imminent.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 2d 63 6f 6e 74 61 63 74 2d 61 62 75 73 65 40 69 6d 6d 69 6e 65 6e 74 6d 65 74 68 6f 64 73 2e 6e 65 74 } //01 00  Please-contact-abuse@imminentmethods.net
		$a_01_1 = {69 66 2d 74 68 69 73 2d 61 73 73 65 6d 62 6c 79 2d 77 61 73 2d 66 6f 75 6e 64 2d 62 65 69 6e 67 2d 75 73 65 64 2d 6d 61 6c 69 63 69 6f 75 73 6c 79 } //01 00  if-this-assembly-was-found-being-used-maliciously
		$a_01_2 = {54 68 69 73 2d 66 69 6c 65 2d 77 61 73 2d 62 75 69 6c 74 2d 75 73 69 6e 67 2d 49 6e 76 69 73 69 62 6c 65 2d 4d 6f 64 65 } //01 00  This-file-was-built-using-Invisible-Mode
		$a_01_3 = {49 6d 6d 69 6e 65 6e 74 2d 4d 6f 6e 69 74 6f 72 2d 43 6c 69 65 6e 74 2d 57 61 74 65 72 6d 61 72 6b } //00 00  Imminent-Monitor-Client-Watermark
	condition:
		any of ($a_*)
 
}