
rule Trojan_Win32_BlackCat_SAA_MTB{
	meta:
		description = "Trojan:Win32/BlackCat.SAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 72 79 69 6e 67 20 74 6f 20 72 65 6d 6f 76 65 20 73 68 61 64 6f 77 20 63 6f 70 69 65 73 } //02 00  Trying to remove shadow copies
		$a_01_1 = {69 6d 70 65 72 73 6e 6f 2d 76 6d 2d 6b 69 6c 6c 6e 6f 2d 76 6d 2d 73 6e 61 70 73 68 6f 74 2d 6b 69 6c 6c 6e 6f 2d 76 6d 2d 6b 69 6c 6c 2d 6e 61 6d 65 73 } //01 00  impersno-vm-killno-vm-snapshot-killno-vm-kill-names
		$a_01_2 = {49 6e 76 61 6c 69 64 20 63 6f 6e 66 69 67 21 } //01 00  Invalid config!
		$a_01_3 = {49 6e 76 61 6c 69 64 20 70 75 62 6c 69 63 20 6b 65 79 } //01 00  Invalid public key
		$a_01_4 = {49 6e 76 61 6c 69 64 20 61 63 63 65 73 73 20 74 6f 6b 65 6e } //01 00  Invalid access token
		$a_01_5 = {70 61 6e 69 63 20 70 61 79 6c 6f 61 64 20 70 61 6e 69 63 6b 65 64 } //00 00  panic payload panicked
	condition:
		any of ($a_*)
 
}