
rule Ransom_Win32_VasaLocker_MK_MTB{
	meta:
		description = "Ransom:Win32/VasaLocker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 08 00 00 0a 00 "
		
	strings :
		$a_81_0 = {65 63 64 68 5f 70 75 62 5f 6b 2e 62 69 6e } //01 00  ecdh_pub_k.bin
		$a_81_1 = {76 61 73 61 5f 64 62 67 2e 74 78 74 } //01 00  vasa_dbg.txt
		$a_81_2 = {56 41 53 41 20 4c 4f 43 4b 45 52 } //0a 00  VASA LOCKER
		$a_81_3 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 73 20 61 6e 64 20 73 65 72 76 65 72 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your computers and servers are encrypted
		$a_81_4 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 68 } //01 00  @protonmail.ch
		$a_81_5 = {59 4f 55 52 20 50 45 52 53 4f 4e 41 4c 20 49 44 2c 20 41 54 54 41 43 48 20 49 54 3a } //0a 00  YOUR PERSONAL ID, ATTACH IT:
		$a_81_6 = {21 21 21 20 44 41 4e 47 45 52 20 21 21 21 } //0a 00  !!! DANGER !!!
		$a_81_7 = {5f 5f 4e 49 53 54 5f 4b 35 37 31 5f 5f } //00 00  __NIST_K571__
		$a_00_8 = {5d 04 00 00 07 6a 04 80 5c 26 00 00 08 6a 04 80 00 00 01 00 03 00 10 00 a3 01 53 74 65 6c 65 67 61 2e 53 53 21 4d 54 42 } //00 00 
	condition:
		any of ($a_*)
 
}