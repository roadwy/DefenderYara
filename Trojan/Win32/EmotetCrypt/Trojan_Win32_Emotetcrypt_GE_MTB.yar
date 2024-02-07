
rule Trojan_Win32_Emotetcrypt_GE_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c8 2b 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 a1 90 01 04 0f af 05 90 01 04 2b c8 2b 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 a1 90 01 04 0f af 05 90 01 04 2b c8 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 90 00 } //01 00 
		$a_81_1 = {41 54 58 23 39 4b 71 6f 40 6a 53 76 25 78 44 71 62 21 69 73 65 75 54 79 4b 37 32 46 69 25 5e 30 6c 4d 6c 75 24 6f 7a 6d 2b 6f 21 72 59 3f 64 77 46 69 43 24 67 75 70 28 56 3c 42 74 43 62 25 6e 53 57 } //00 00  ATX#9Kqo@jSv%xDqb!iseuTyK72Fi%^0lMlu$ozm+o!rY?dwFiC$gup(V<BtCb%nSW
	condition:
		any of ($a_*)
 
}