
rule Trojan_Win32_Iyeclore_C_bit{
	meta:
		description = "Trojan:Win32/Iyeclore.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 75 6e 63 74 69 6f 6e 20 43 6c 69 63 6b 41 44 28 61 64 63 6f 64 65 29 7b 6c 6e 6b 20 3d 20 64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 42 79 49 64 28 22 61 64 69 64 22 29 3b 20 69 66 28 6c 6e 6b 21 3d 6e 75 6c 6c 29 7b 6c 6e 6b 2e 68 72 65 66 3d 61 64 63 6f 64 65 3b 6c 6e 6b 2e 63 6c 69 63 6b 28 29 3b 7d 7d } //01 00 
		$a_03_1 = {8b 45 fc 8b 08 ff 51 90 01 01 ba 90 01 04 8b 45 fc 8b 08 ff 51 90 01 01 ba 90 01 04 8b 45 fc 8b 08 ff 51 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}