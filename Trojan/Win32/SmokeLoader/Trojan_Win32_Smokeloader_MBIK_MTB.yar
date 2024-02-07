
rule Trojan_Win32_Smokeloader_MBIK_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MBIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 2b c8 8a 10 ff 4d 10 88 14 01 40 83 7d 10 00 75 f1 } //01 00 
		$a_01_1 = {44 69 6a 69 72 6f 62 65 62 61 67 65 72 20 77 65 7a 69 73 69 73 6f 78 65 77 61 6e 61 20 64 6f 6d 65 73 65 } //01 00  Dijirobebager wezisisoxewana domese
		$a_01_2 = {54 65 78 6f 73 69 6b 75 68 6f 6e 20 66 69 70 75 7a 65 63 } //01 00  Texosikuhon fipuzec
		$a_01_3 = {63 69 63 6f 6b 69 72 61 66 69 6e 69 62 69 72 6f 7a 61 74 75 77 61 6a } //00 00  cicokirafinibirozatuwaj
	condition:
		any of ($a_*)
 
}