
rule Trojan_Win32_NSISInject_FQ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 46 6f 72 73 76 61 72 73 63 68 65 66 73 5c 52 65 6c 69 6b 76 69 65 73 6b 72 69 6e 65 74 73 2e 69 6e 69 } //01 00  \Forsvarschefs\Relikvieskrinets.ini
		$a_81_1 = {4e 73 6b 65 66 6f 72 65 73 74 69 6c 6c 69 6e 67 65 72 73 } //01 00  Nskeforestillingers
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 53 74 79 72 61 78 65 73 5c 49 74 61 6c 69 63 69 73 69 6e 67 } //01 00  Software\Styraxes\Italicising
		$a_81_3 = {5c 6b 6c 61 6d 72 65 61 62 65 6e 5c 74 72 79 6b 6b 6f 67 65 72 6e 65 5c 4c 69 67 6e 69 6e 67 65 72 6e 65 73 } //01 00  \klamreaben\trykkogerne\Ligningernes
		$a_81_4 = {47 6c 61 63 69 61 6c 69 7a 65 31 33 30 2e 55 67 65 } //00 00  Glacialize130.Uge
	condition:
		any of ($a_*)
 
}