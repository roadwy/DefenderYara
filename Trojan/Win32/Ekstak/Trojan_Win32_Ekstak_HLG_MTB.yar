
rule Trojan_Win32_Ekstak_HLG_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.HLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 0c 53 56 57 e9 90 01 03 01 90 00 } //01 00 
		$a_01_1 = {40 2e 72 69 67 63 } //01 00  @.rigc
		$a_01_2 = {4c 64 72 55 6e 6c 6f 63 6b 4c 6f 61 64 65 72 4c 6f 63 6b } //01 00  LdrUnlockLoaderLock
		$a_01_3 = {40 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //00 00  @GetProcAddress
	condition:
		any of ($a_*)
 
}