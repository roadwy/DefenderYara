
rule Trojan_Win64_Bazarcrypt_GD_MTB{
	meta:
		description = "Trojan:Win64/Bazarcrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_02_0 = {03 c1 99 41 f7 90 02 02 8d 1c 90 02 02 ff 15 90 02 04 44 8a 90 02 04 4c 63 90 02 02 49 83 90 02 02 01 41 0f b6 90 02 02 41 02 90 02 02 43 32 90 02 04 48 83 90 02 02 01 41 88 90 02 04 74 09 44 8b 90 02 06 eb 90 00 } //01 00 
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  01 00 
		$a_80_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //LoadResource  00 00 
	condition:
		any of ($a_*)
 
}