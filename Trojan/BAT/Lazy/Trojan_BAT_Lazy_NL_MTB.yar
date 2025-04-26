
rule Trojan_BAT_Lazy_NL_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 bd 00 00 70 13 04 72 a3 00 00 70 13 05 73 ?? 00 00 0a 13 06 } //3
		$a_01_1 = {43 6f 6e 71 75 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Conquer.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_BAT_Lazy_NL_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 7b 00 00 0a 02 6f ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 06 6f ?? 00 00 0a 28 28 00 00 06 } //5
		$a_01_1 = {4b 65 79 41 75 74 68 20 4c 6f 61 64 65 72 20 57 69 6e 66 6f 72 6d 20 45 78 61 6d 70 6c 65 } //1 KeyAuth Loader Winform Example
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Lazy_NL_MTB_3{
	meta:
		description = "Trojan:BAT/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 95 01 00 70 06 73 ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a } //5
		$a_01_1 = {43 4f 4c 4c 45 43 54 42 49 4f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 COLLECTBIO.Properties.Resources.resources
		$a_01_2 = {43 4f 4c 4c 45 43 54 42 49 4f } //1 COLLECTBIO
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_Lazy_NL_MTB_4{
	meta:
		description = "Trojan:BAT/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 41 01 00 70 13 0b 11 05 72 fe 01 00 70 72 41 01 00 70 6f 27 00 00 0a 13 0c 11 07 16 fe 04 16 fe 01 13 0d 11 0d 2c 3b 00 02 7b 0c 00 00 04 } //3
		$a_01_1 = {72 e5 02 00 70 72 e0 01 00 70 28 23 00 00 0a 26 20 ee 02 00 00 28 03 00 00 0a 00 72 0f 03 00 70 28 35 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}