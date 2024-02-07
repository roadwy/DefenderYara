
rule Backdoor_Win32_Androme_PB_MTB{
	meta:
		description = "Backdoor:Win32/Androme.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {46 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8b 84 b5 90 01 04 03 45 90 01 01 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 89 45 f0 8a 84 b5 90 01 04 8b 55 90 01 01 8b 94 95 90 01 04 89 94 b5 90 01 04 25 ff 00 00 00 8b 55 90 01 01 89 84 95 90 01 04 8b 84 b5 90 01 04 8b 55 90 01 01 03 84 95 90 01 04 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 90 01 04 8b 55 90 01 01 30 04 3a 47 4b 0f 85 90 00 } //01 00 
		$a_01_1 = {3a 5c 20 43 6f 6e 6e 65 63 74 65 64 } //01 00  :\ Connected
		$a_01_2 = {45 6a 65 63 74 20 55 53 42 } //00 00  Eject USB
		$a_00_3 = {5d 04 00 00 d1 } //fa 03 
	condition:
		any of ($a_*)
 
}