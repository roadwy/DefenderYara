
rule Trojan_Win32_IcedId_DEG_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 10 8d 44 24 1c 53 6a 01 53 53 50 ff 15 90 01 04 85 c0 5e 75 3b 6a 08 6a 01 53 8d 4c 24 24 53 51 ff 15 90 1b 00 85 c0 90 00 } //01 00 
		$a_81_1 = {48 37 47 78 39 6f 70 32 4a 70 5a 33 42 77 71 74 6a 52 32 50 67 4f 63 6e 6c 6f 33 4d 73 55 42 69 6d 61 65 42 67 68 33 47 76 50 56 70 4c 4a 75 5a 66 48 41 64 66 4f 6d 75 76 73 6f 6c 48 5a 65 45 79 51 51 47 69 45 30 49 68 6a 64 4e 6a } //00 00 
	condition:
		any of ($a_*)
 
}