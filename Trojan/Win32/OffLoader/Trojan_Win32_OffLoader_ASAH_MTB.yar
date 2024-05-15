
rule Trojan_Win32_OffLoader_ASAH_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ASAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {70 00 6c 00 65 00 61 00 73 00 75 00 72 00 65 00 66 00 6c 00 79 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 74 00 72 00 61 00 63 00 6b 00 65 00 72 00 2f 00 74 00 68 00 61 00 6e 00 6b 00 5f 00 79 00 6f 00 75 00 2e 00 70 00 68 00 70 00 } //01 00  pleasurefly.online/tracker/thank_you.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //01 00  /silent
		$a_01_2 = {49 00 20 00 77 00 61 00 6e 00 74 00 20 00 74 00 6f 00 20 00 6d 00 61 00 6e 00 75 00 61 00 6c 00 6c 00 79 00 20 00 72 00 65 00 62 00 6f 00 6f 00 74 00 20 00 6c 00 61 00 74 00 65 00 72 00 } //00 00  I want to manually reboot later
	condition:
		any of ($a_*)
 
}