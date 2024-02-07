
rule Trojan_BAT_FormBook_AGDP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 73 73 65 65 65 } //01 00  ssseee
		$a_01_1 = {53 68 61 68 69 64 } //01 00  Shahid
		$a_01_2 = {50 00 23 00 65 00 73 00 2e 00 57 00 68 00 23 00 74 00 65 00 } //01 00  P#es.Wh#te
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_4 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 } //01 00  System.Convert
		$a_01_5 = {45 00 73 00 69 00 6e 00 69 00 42 00 75 00 6c 00 47 00 61 00 6d 00 65 00 } //01 00  EsiniBulGame
		$a_01_6 = {54 00 6f 00 42 00 79 00 74 00 65 00 } //00 00  ToByte
	condition:
		any of ($a_*)
 
}