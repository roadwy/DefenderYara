
rule Trojan_BAT_LummaStealer_RDG_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 33 65 37 62 31 64 39 2d 66 32 63 35 2d 34 61 39 32 2d 39 62 32 33 2d 36 66 37 63 38 65 34 64 39 31 30 31 } //1 c3e7b1d9-f2c5-4a92-9b23-6f7c8e4d9101
		$a_01_1 = {41 65 74 68 65 72 44 79 6e 61 6d 69 63 73 } //1 AetherDynamics
		$a_01_2 = {41 65 74 68 65 72 20 41 64 76 61 6e 63 65 64 20 53 75 69 74 65 } //1 Aether Advanced Suite
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}