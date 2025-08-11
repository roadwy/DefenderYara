
rule Trojan_Win64_KatzStealer_RH_MTB{
	meta:
		description = "Trojan:Win64/KatzStealer.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 64 86 0b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 02 2b 00 84 0d 00 00 e2 10 00 00 0e 00 00 20 13 00 00 00 10 } //3
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 73 65 74 20 70 72 6f 78 79 20 62 6c 61 6e 6b 65 74 2e } //1 Failed to set proxy blanket.
		$a_01_2 = {44 65 63 72 79 70 74 69 6f 6e 20 66 61 69 6c 65 64 2e 20 4c 61 73 74 20 65 72 72 6f 72 3a } //1 Decryption failed. Last error:
		$a_01_3 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 4c 6f 63 61 6c 20 53 74 61 74 65 } //1 \Google\Chrome\User Data\Local State
		$a_00_4 = {25 00 73 00 5c 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 5f 00 61 00 70 00 70 00 62 00 6f 00 75 00 6e 00 64 00 5f 00 6b 00 65 00 79 00 2e 00 74 00 78 00 74 00 } //2 %s\decrypted_appbound_key.txt
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*2) >=8
 
}