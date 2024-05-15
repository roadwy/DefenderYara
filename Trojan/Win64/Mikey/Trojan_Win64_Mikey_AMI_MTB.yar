
rule Trojan_Win64_Mikey_AMI_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 8b df eb 38 48 8d 15 f3 a5 00 00 48 8b cb ff 15 9a 1e 00 00 48 85 c0 74 e6 48 8d 15 f6 a5 00 00 48 89 05 27 fb 00 00 48 8b cb ff 15 7e 1e 00 00 48 85 c0 74 ca } //02 00 
		$a_01_1 = {ff 48 85 d2 7e 24 49 2b f6 4b 8b 8c eb 50 69 02 00 49 03 ce 42 8a 04 36 42 88 44 f9 3e ff c7 49 ff c6 48 63 c7 48 3b c2 } //01 00 
		$a_01_2 = {6e 6f 64 65 5f 6d 6f 64 75 6c 65 73 5c 77 69 6e 64 6f 33 32 6c 69 62 5c 62 75 69 6c 64 5c 52 65 6c 65 61 73 65 5c 77 69 6e 64 6f 33 32 6c 69 62 2e 70 64 62 } //00 00  node_modules\windo32lib\build\Release\windo32lib.pdb
	condition:
		any of ($a_*)
 
}