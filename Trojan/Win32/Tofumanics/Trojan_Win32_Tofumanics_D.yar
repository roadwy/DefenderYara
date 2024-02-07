
rule Trojan_Win32_Tofumanics_D{
	meta:
		description = "Trojan:Win32/Tofumanics.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {67 6f 74 6f 20 30 90 02 10 65 72 61 73 65 20 22 90 02 10 72 65 61 64 6d 65 2e 74 78 74 22 90 00 } //01 00 
		$a_03_1 = {79 65 73 2e 74 78 74 90 02 07 2f 63 20 63 6d 64 20 2f 63 20 73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30 90 00 } //01 00 
		$a_01_2 = {8b 08 ff 51 08 b8 60 ea 00 00 e8 } //01 00 
		$a_01_3 = {2f 63 20 65 72 61 73 65 20 22 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //00 00  /c erase "C:\WINDOWS\system32\drivers\etc\hosts
	condition:
		any of ($a_*)
 
}