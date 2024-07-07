
rule Trojan_Win64_Growtopia_NA_MTB{
	meta:
		description = "Trojan:Win64/Growtopia.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 73 63 65 6e 74 20 50 72 65 6d 69 75 6d 20 50 72 6f 78 79 2e 70 64 62 } //1 Ascent Premium Proxy.pdb
		$a_01_1 = {44 65 63 6f 64 65 64 20 49 74 65 6d 73 } //1 Decoded Items
		$a_01_2 = {55 6e 61 62 6c 65 20 54 6f 20 73 65 72 69 61 6c 69 7a 65 20 74 68 69 73 20 77 6f 72 6c 64 } //1 Unable To serialize this world
		$a_01_3 = {53 6f 6d 65 74 68 69 6e 67 20 67 6f 6e 65 20 77 72 6f 6e 67 20 77 68 69 6c 65 20 64 65 63 6f 64 69 6e 67 20 2e 64 61 74 20 66 69 6c 65 21 } //1 Something gone wrong while decoding .dat file!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}