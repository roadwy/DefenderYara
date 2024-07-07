
rule Trojan_BAT_NjRat_NEDT_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 64 36 35 32 61 66 65 2d 30 30 35 38 2d 34 33 38 61 2d 61 37 36 32 2d 33 36 64 34 36 64 38 63 32 65 31 63 } //5 ed652afe-0058-438a-a762-36d46d8c2e1c
		$a_01_1 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //2 RPF:SmartAssembly
		$a_01_2 = {6b 5a 5a 41 49 41 4f 35 59 6a 6f 4c 52 49 41 55 64 77 } //2 kZZAIAO5YjoLRIAUdw
		$a_01_3 = {53 68 61 72 70 5a 69 70 4c 69 62 } //2 SharpZipLib
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=11
 
}