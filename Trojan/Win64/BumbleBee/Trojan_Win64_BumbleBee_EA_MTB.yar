
rule Trojan_Win64_BumbleBee_EA_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 64 72 41 64 64 78 36 34 2e 64 6c 6c } //01 00  LdrAddx64.dll
		$a_01_1 = {61 43 6d 48 6d 6a 72 70 74 53 } //01 00  aCmHmjrptS
		$a_01_2 = {53 65 74 50 61 74 68 } //01 00  SetPath
		$a_01_3 = {5a 00 3a 00 5c 00 68 00 6f 00 6f 00 6b 00 65 00 72 00 32 00 } //01 00  Z:\hooker2
		$a_01_4 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //00 00  CreateDirectoryA
	condition:
		any of ($a_*)
 
}