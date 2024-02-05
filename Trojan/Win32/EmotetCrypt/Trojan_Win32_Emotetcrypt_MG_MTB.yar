
rule Trojan_Win32_Emotetcrypt_MG_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 08 68 90 02 04 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 81 ec 4c 01 00 00 53 56 57 89 65 f8 c7 45 fc 90 02 04 8b 5d 08 b9 3e 00 00 00 33 c0 8d bd 90 02 04 f3 ab 90 00 } //01 00 
		$a_00_1 = {6a 40 68 00 10 00 00 51 6a 00 ff 15 } //01 00 
		$a_00_2 = {5f 5e 64 89 0d 00 00 00 00 5b 8b e5 5d c2 0c 00 } //01 00 
		$a_80_3 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //RtlMoveMemory  00 00 
	condition:
		any of ($a_*)
 
}