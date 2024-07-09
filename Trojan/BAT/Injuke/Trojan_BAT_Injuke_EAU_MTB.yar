
rule Trojan_BAT_Injuke_EAU_MTB{
	meta:
		description = "Trojan:BAT/Injuke.EAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0a 28 02 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 02 07 28 ?? 00 00 06 0c dd ?? 00 00 00 26 dd ?? ff ff ff 08 2a } //3
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 34 00 37 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 WindowsFormsApp47.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}