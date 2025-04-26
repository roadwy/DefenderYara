
rule Trojan_BAT_LummaStealer_RDE_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 6b 79 48 69 67 68 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 20 54 72 61 64 65 6d 61 72 6b } //1 SkyHigh Technologies Trademark
		$a_01_1 = {52 65 76 6f 6c 75 74 69 6f 6e 69 7a 69 6e 67 20 63 6f 6e 6e 65 63 74 69 76 69 74 79 20 77 69 74 68 20 63 75 74 74 69 6e 67 2d 65 64 67 65 20 63 6c 6f 75 64 20 73 6f 6c 75 74 69 6f 6e 73 2e } //1 Revolutionizing connectivity with cutting-edge cloud solutions.
		$a_01_2 = {51 75 61 6e 74 75 6d 57 61 76 65 } //1 QuantumWave
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}