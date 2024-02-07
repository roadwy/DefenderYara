
rule Trojan_Win32_Emotetcrypt_GJ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b ca 8b 15 90 01 04 0f af 15 90 01 04 03 ca 2b 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 2b ca 2b 0d 90 01 04 2b 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 2b ca 8b 55 08 0f b6 0c 0a 8b 55 0c 0f b6 04 02 33 c1 90 00 } //01 00 
		$a_81_1 = {58 3e 4a 54 51 28 44 6b 54 25 78 6b 48 5e 38 4a 70 52 40 40 38 77 58 6a 79 68 5a 6f 79 44 45 46 37 67 23 31 6b 4c 44 70 6d 32 33 70 41 49 32 75 6c 77 77 79 65 56 } //00 00  X>JTQ(DkT%xkH^8JpR@@8wXjyhZoyDEF7g#1kLDpm23pAI2ulwwyeV
	condition:
		any of ($a_*)
 
}