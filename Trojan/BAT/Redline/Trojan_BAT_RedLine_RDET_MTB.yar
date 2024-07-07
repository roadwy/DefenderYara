
rule Trojan_BAT_RedLine_RDET_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 65 63 68 4e 6f 76 61 20 53 6f 6c 75 74 69 6f 6e 73 20 53 75 69 74 65 } //1 TechNova Solutions Suite
		$a_01_1 = {4c 65 61 64 69 6e 67 20 69 6e 6e 6f 76 61 74 69 6f 6e 20 66 6f 72 20 61 20 63 6f 6e 6e 65 63 74 65 64 20 77 6f 72 6c 64 2e } //1 Leading innovation for a connected world.
		$a_01_2 = {41 6c 70 68 61 } //1 Alpha
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}