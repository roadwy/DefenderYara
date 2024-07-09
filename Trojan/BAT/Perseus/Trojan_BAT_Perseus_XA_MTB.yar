
rule Trojan_BAT_Perseus_XA_MTB{
	meta:
		description = "Trojan:BAT/Perseus.XA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,40 00 3f 00 08 00 00 "
		
	strings :
		$a_00_0 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_00_1 = {44 65 63 6f 6d 70 72 65 73 73 47 5a 69 70 } //1 DecompressGZip
		$a_00_2 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //1 ConfusedByAttribute
		$a_03_3 = {63 6f 73 74 75 72 61 2e [0-08] 2e 64 6c 6c 2e 64 6c 6c 2e 7a 69 70 } //20
		$a_03_4 = {63 6f 73 74 75 72 61 2e [0-08] 2e 64 6c 6c 2e 70 64 62 2e 7a 69 70 } //20
		$a_00_5 = {57 61 76 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //20 Waves.Resources.resources
		$a_00_6 = {74 6f 74 6f } //1 toto
		$a_00_7 = {57 61 76 65 73 2e 70 64 62 } //1 Waves.pdb
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*20+(#a_03_4  & 1)*20+(#a_00_5  & 1)*20+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=63
 
}