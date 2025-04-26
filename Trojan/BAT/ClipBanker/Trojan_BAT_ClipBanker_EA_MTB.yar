
rule Trojan_BAT_ClipBanker_EA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {39 00 62 00 61 00 63 00 61 00 64 00 61 00 65 00 61 00 66 00 61 00 67 00 61 00 68 00 61 00 } //1 9bacadaeafagaha
		$a_01_1 = {69 00 73 00 20 00 74 00 61 00 6d 00 70 00 65 00 72 00 65 00 64 00 2e 00 } //1 is tampered.
		$a_01_2 = {43 6c 69 70 70 65 72 42 75 69 6c 64 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 ClipperBuild.g.resources
		$a_01_3 = {63 6f 73 74 75 72 61 2e 64 6f 74 6e 65 74 7a 69 70 2e 70 64 62 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 costura.dotnetzip.pdb.compressed
		$a_01_4 = {49 73 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 41 76 61 69 6c 61 62 6c 65 } //1 IsClipboardFormatAvailable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}