
rule Trojan_Win64_Sirefef_AI{
	meta:
		description = "Trojan:Win64/Sirefef.AI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 2e 72 65 70 6c 61 63 65 28 27 61 62 6f 75 74 3a 62 6c 61 6e 6b 27 29 3b 7d 7d 65 6c 73 65 7b 6b 2e 72 65 70 6c 61 63 65 28 75 72 6c 29 3b 7d 7d } //01 00  k.replace('about:blank');}}else{k.replace(url);}}
		$a_01_1 = {33 c0 48 89 07 48 89 47 08 48 89 47 10 48 89 47 18 c7 47 30 63 6e 63 74 48 89 47 28 } //00 00 
	condition:
		any of ($a_*)
 
}