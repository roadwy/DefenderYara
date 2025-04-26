
rule Trojan_Win64_LucaStealer_GPA_MTB{
	meta:
		description = "Trojan:Win64/LucaStealer.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 72 65 67 65 78 5c 73 74 72 69 6e 67 2e 72 73 } //1 \regex\string.rs
		$a_01_1 = {5c 64 65 66 65 6e 73 65 5c 61 6e 74 69 5f 64 62 67 2e 72 73 } //1 \defense\anti_dbg.rs
		$a_01_2 = {5c 64 65 66 65 6e 73 65 5c 61 6e 74 69 5f 76 6d 2e 72 73 } //1 \defense\anti_vm.rs
		$a_01_3 = {5c 64 69 73 63 6f 72 64 2e 72 73 } //1 \discord.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}