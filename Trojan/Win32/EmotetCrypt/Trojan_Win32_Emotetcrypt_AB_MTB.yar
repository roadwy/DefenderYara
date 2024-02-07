
rule Trojan_Win32_Emotetcrypt_AB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.AB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 36 4e 77 6b 33 2a 41 33 49 63 45 49 4b 65 24 4a 3e 49 65 69 3c 3f 47 52 64 34 6a 79 63 30 39 59 52 45 61 40 2b 54 59 3c 21 65 2b 45 58 42 53 45 44 58 6e 59 6e 77 70 45 3c 69 57 25 73 6a 56 59 38 30 43 5e 73 63 3c 41 51 23 77 63 57 75 4d 70 62 4f 28 74 69 42 55 6d 44 5e 54 72 4e 28 35 62 29 2b 74 72 5a 76 71 4c 56 35 24 41 2a 37 31 56 5a } //00 00  p6Nwk3*A3IcEIKe$J>Iei<?GRd4jyc09YREa@+TY<!e+EXBSEDXnYnwpE<iW%sjVY80C^sc<AQ#wcWuMpbO(tiBUmD^TrN(5b)+trZvqLV5$A*71VZ
	condition:
		any of ($a_*)
 
}