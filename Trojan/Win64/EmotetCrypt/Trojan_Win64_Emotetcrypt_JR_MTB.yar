
rule Trojan_Win64_Emotetcrypt_JR_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 b8 0d ce c7 e0 7c 0c ce c7 ff c7 49 f7 e3 48 c1 ea 05 48 6b d2 29 4c 2b da 4d 03 d8 4d 03 df 4d 03 dd 43 8a 04 33 4c 63 df 32 01 48 ff c1 88 06 48 ff c6 4c 3b db 72 } //0a 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_2 = {5e 36 76 2b 78 6a 65 61 77 3f 30 37 21 30 63 46 46 40 46 55 4f 42 77 4f 29 76 24 71 53 70 36 69 30 4f 46 51 41 58 40 68 } //00 00  ^6v+xjeaw?07!0cFF@FUOBwO)v$qSp6i0OFQAX@h
	condition:
		any of ($a_*)
 
}