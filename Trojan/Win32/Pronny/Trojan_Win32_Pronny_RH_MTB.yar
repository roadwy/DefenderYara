
rule Trojan_Win32_Pronny_RH_MTB{
	meta:
		description = "Trojan:Win32/Pronny.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {6f 6c 31 00 6e 6b 2e d5 00 8b 85 52 a7 b4 45 99 0b 66 ab 2c 99 24 41 } //01 00 
		$a_01_1 = {48 00 6f 00 6d 00 69 00 6c 00 69 00 61 00 72 00 79 00 20 00 55 00 6e 00 62 00 72 00 69 00 65 00 66 00 6c 00 79 00 20 00 6c 00 69 00 6e 00 64 00 6f 00 6e 00 } //01 00 
		$a_01_2 = {73 00 65 00 6e 00 73 00 61 00 74 00 69 00 6f 00 6e 00 69 00 73 00 74 00 69 00 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}