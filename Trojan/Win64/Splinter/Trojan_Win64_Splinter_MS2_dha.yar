
rule Trojan_Win64_Splinter_MS2_dha{
	meta:
		description = "Trojan:Win64/Splinter.MS2!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 69 6e 69 74 69 61 6c 69 7a 65 20 69 6d 70 6c 61 6e 74 } //1 Failed to initialize implant
		$a_01_1 = {73 70 6c 69 6e 74 65 72 5f 63 6f 72 65 5c 63 32 5f 63 6c 69 65 6e 74 5c 73 72 63 5c 6c 69 62 2e 72 73 } //1 splinter_core\c2_client\src\lib.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}