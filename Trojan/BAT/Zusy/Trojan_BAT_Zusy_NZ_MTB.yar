
rule Trojan_BAT_Zusy_NZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 68 00 00 0a 02 6f ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 06 6f ?? 00 00 0a 28 23 00 00 06 } //5
		$a_01_1 = {4d 65 6c 6f 6e 53 70 6f 6f 66 65 72 5f 62 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 MelonSpoofer_b2.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Zusy_NZ_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 28 06 00 00 06 75 ?? ?? ?? 1b 28 ?? ?? ?? 0a 13 04 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff dd ?? ?? ?? ff 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff } //5
		$a_01_1 = {4d 6b 77 69 6d 73 63 78 76 61 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Mkwimscxva.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}