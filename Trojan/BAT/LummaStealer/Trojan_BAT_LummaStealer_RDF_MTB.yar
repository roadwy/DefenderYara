
rule Trojan_BAT_LummaStealer_RDF_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 65 6c 65 73 74 69 61 6c 20 49 6e 6e 6f 76 61 74 69 6f 6e 73 20 54 72 61 64 65 6d 61 72 6b } //1 Celestial Innovations Trademark
		$a_01_1 = {49 6e 6e 6f 76 61 74 69 76 65 20 73 6f 6c 75 74 69 6f 6e 73 20 64 72 69 76 69 6e 67 20 74 68 65 20 66 75 74 75 72 65 20 6f 66 20 74 65 63 68 6e 6f 6c 6f 67 79 } //1 Innovative solutions driving the future of technology
		$a_01_2 = {61 37 66 38 64 36 62 34 2d 65 39 64 33 2d 34 30 31 39 2d 38 62 32 34 2d 39 38 37 36 35 62 63 64 65 66 31 32 } //1 a7f8d6b4-e9d3-4019-8b24-98765bcdef12
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}