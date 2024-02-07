
rule Trojan_BAT_RedLine_NFK_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 ff a2 3f 09 1e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 11 01 00 00 95 00 00 00 8b 01 00 00 07 } //02 00 
		$a_01_1 = {6b 61 73 64 69 68 62 66 70 66 64 75 71 77 } //02 00  kasdihbfpfduqw
		$a_01_2 = {35 4b 20 50 6c 61 79 65 72 } //02 00  5K Player
		$a_01_3 = {58 52 61 69 6c 73 2e 43 6c 61 73 73 73 65 73 } //01 00  XRails.Classses
		$a_01_4 = {4e 61 74 69 76 65 4d 65 74 68 6f 64 73 } //01 00  NativeMethods
		$a_01_5 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //01 00  get_encrypted_key
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_01_7 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //01 00  BitConverter
		$a_01_8 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_9 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //00 00  ConfusedByAttribute
	condition:
		any of ($a_*)
 
}