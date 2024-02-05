
rule Trojan_Win32_Fareit_RPB_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {be ff ff ff 0f bf 01 00 00 00 6a 00 ff 15 90 01 04 2b f7 75 f4 68 90 01 04 ff 15 90 01 04 a1 90 01 04 29 05 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 a1 90 01 04 1b ca 3b c8 89 0d 90 01 04 7c 90 01 01 7f 90 09 20 00 90 02 20 ff 15 90 01 04 68 90 01 04 ff 15 90 00 } //01 00 
		$a_01_1 = {6b 00 45 00 72 00 6e 00 45 00 6c 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 00 00 00 00 6b 45 72 6e 45 6c 33 32 2e 44 4c 4c } //00 00 
	condition:
		any of ($a_*)
 
}