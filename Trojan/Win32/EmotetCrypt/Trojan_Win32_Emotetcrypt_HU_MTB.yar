
rule Trojan_Win32_Emotetcrypt_HU_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2b 03 c2 99 bd 90 01 04 f7 fd a1 90 01 04 0f af c7 5d 2b e8 0f af e9 8d 44 0f 02 0f af c6 2b e8 a1 90 01 04 0f af c0 03 e8 6b ed 03 03 d5 8d 04 09 2b d0 2b 54 24 20 8b 44 24 2c 03 15 90 01 04 03 d6 8a 0c 1a 30 08 90 00 } //1
		$a_81_1 = {46 57 34 42 31 57 71 4f 30 48 6d 72 40 26 74 70 5f 7a 3c 31 75 47 79 48 63 46 3e 50 5e 45 49 39 26 53 48 41 3c 53 2a 69 31 70 75 5e 4e 26 } //1 FW4B1WqO0Hmr@&tp_z<1uGyHcF>P^EI9&SHA<S*i1pu^N&
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}