
rule Trojan_Win32_Emotetcrypt_RTA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {41 54 58 23 39 4b 71 6f 40 6a 53 76 25 78 44 71 62 21 69 73 65 75 54 79 4b 37 32 46 69 25 5e 30 6c 4d 6c 75 24 6f 7a 6d 2b 6f 21 72 59 3f 64 77 46 69 43 24 67 75 70 28 56 3c 42 74 43 62 25 6e 53 57 } //ATX#9Kqo@jSv%xDqb!iseuTyK72Fi%^0lMlu$ozm+o!rY?dwFiC$gup(V<BtCb%nSW  1
		$a_03_1 = {6a 40 68 00 30 00 00 8b 4d ?? 51 6a 00 6a ff } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}