
rule Trojan_Win64_DiscordStealer_AHC_MTB{
	meta:
		description = "Trojan:Win64/DiscordStealer.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 72 61 62 62 65 72 5c 67 72 61 62 62 65 72 2e 72 73 } //10 grabber\grabber.rs
		$a_01_1 = {65 76 61 73 69 6f 6e 5c 70 72 6f 63 65 73 73 2e 72 73 } //20 evasion\process.rs
		$a_01_2 = {65 76 61 73 69 6f 6e 5c 76 6d 2e 72 73 } //30 evasion\vm.rs
		$a_01_3 = {73 72 63 5c 67 6c 6f 62 61 6c 5c 6c 6f 61 64 65 72 2e 72 73 } //40 src\global\loader.rs
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}