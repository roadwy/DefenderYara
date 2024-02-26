
rule Trojan_Win64_RustStealer_RPY_MTB{
	meta:
		description = "Trojan:Win64/RustStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 75 64 20 4d 65 20 62 79 20 4e 65 77 20 43 6f 64 65 72 20 52 75 73 74 } //01 00  Fud Me by New Coder Rust
		$a_01_1 = {53 65 63 75 72 65 5f 56 6f 72 74 65 78 } //01 00  Secure_Vortex
		$a_01_2 = {66 68 6e 69 72 } //01 00  fhnir
		$a_01_3 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //01 00  NtWriteVirtualMemory
		$a_01_4 = {70 61 6e 69 63 6b 65 64 } //01 00  panicked
		$a_01_5 = {47 6f 41 77 61 79 } //00 00  GoAway
	condition:
		any of ($a_*)
 
}