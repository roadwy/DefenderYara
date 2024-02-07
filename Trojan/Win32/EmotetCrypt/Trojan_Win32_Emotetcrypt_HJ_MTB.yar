
rule Trojan_Win32_Emotetcrypt_HJ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d0 03 15 90 01 04 2b 15 90 01 04 2b 15 90 01 04 03 15 90 01 04 2b 15 90 01 04 2b 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 2b d0 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 2b d0 8b 45 08 0f b6 14 10 8b 45 0c 0f b6 0c 08 33 ca 8b 15 90 01 04 0f af 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 8b 35 90 01 04 0f af 35 90 01 04 0f af 35 90 00 } //01 00 
		$a_81_1 = {21 6c 58 70 2a 38 6f 5a 50 47 4c 61 5a 6a 4c 21 77 32 46 32 34 50 68 64 73 49 49 33 30 50 38 25 76 5e 28 62 3c 32 77 6b 68 63 79 41 44 48 75 69 72 77 28 30 37 30 3c 41 5f 29 3e 4c 3e 41 76 6d 24 } //00 00  !lXp*8oZPGLaZjL!w2F24PhdsII30P8%v^(b<2wkhcyADHuirw(070<A_)>L>Avm$
	condition:
		any of ($a_*)
 
}