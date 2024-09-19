
rule Trojan_Win64_Relatsnif_E{
	meta:
		description = "Trojan:Win64/Relatsnif.E,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 72 65 6e 61 6d 65 20 7b 7d 20 74 6f 20 7b 7d 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a 20 7b 7d } //1 Failed to rename {} to {}. Error code: {}
		$a_01_1 = {52 65 6e 61 6d 65 64 20 7b 7d 20 74 6f 20 7b 7d 2e } //1 Renamed {} to {}.
		$a_01_2 = {46 69 6c 65 20 7b 7d 20 7b 7d 2e } //1 File {} {}.
		$a_01_3 = {7b 7d 20 7b 7d 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a 20 7b 7d } //1 {} {}. Error code: {}
		$a_01_4 = {4f 76 65 72 77 72 6f 74 65 20 7b 7d 20 77 69 74 68 20 7b 7d 20 7b 7d 20 7b 7d 29 } //1 Overwrote {} with {} {} {})
		$a_01_5 = {5b 7b 7d 5d 20 5b 7b 7d 5d 20 7b 7d } //1 [{}] [{}] {}
		$a_01_6 = {7b 7d 20 7b 7d 20 61 66 74 65 72 20 72 65 6e 61 6d 69 6e 67 20 69 74 2e } //1 {} {} after renaming it.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}