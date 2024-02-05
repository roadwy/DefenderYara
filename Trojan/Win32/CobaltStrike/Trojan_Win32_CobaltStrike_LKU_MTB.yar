
rule Trojan_Win32_CobaltStrike_LKU_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.LKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 40 3c 31 04 11 83 c2 04 8b 45 90 01 01 01 45 90 01 01 8b 0d 90 01 04 8b 45 90 01 06 01 81 ac 00 00 00 81 fa 90 01 04 7c 90 00 } //01 00 
		$a_03_1 = {01 41 40 8b 0d 90 01 04 8b 81 d0 00 00 00 35 90 01 04 09 41 40 b8 90 01 04 2b 86 80 00 00 00 01 05 90 01 04 81 ff 90 01 02 00 00 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}