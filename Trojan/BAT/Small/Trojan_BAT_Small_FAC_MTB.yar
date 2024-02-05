
rule Trojan_BAT_Small_FAC_MTB{
	meta:
		description = "Trojan:BAT/Small.FAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {07 08 9a 0a 06 28 90 01 03 06 20 c4 09 00 00 28 90 01 03 0a de 03 90 00 } //04 00 
		$a_80_1 = {4c 69 73 74 55 52 4c 53 } //ListURLS  04 00 
		$a_80_2 = {50 61 79 6c 6f 61 64 } //Payload  04 00 
		$a_80_3 = {46 65 74 63 68 46 69 6c 65 73 } //FetchFiles  04 00 
		$a_80_4 = {49 6e 74 72 6e 65 74 } //Intrnet  04 00 
		$a_80_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  00 00 
	condition:
		any of ($a_*)
 
}