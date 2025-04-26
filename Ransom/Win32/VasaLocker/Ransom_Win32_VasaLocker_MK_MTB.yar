
rule Ransom_Win32_VasaLocker_MK_MTB{
	meta:
		description = "Ransom:Win32/VasaLocker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 08 00 00 "
		
	strings :
		$a_81_0 = {65 63 64 68 5f 70 75 62 5f 6b 2e 62 69 6e } //10 ecdh_pub_k.bin
		$a_81_1 = {76 61 73 61 5f 64 62 67 2e 74 78 74 } //1 vasa_dbg.txt
		$a_81_2 = {56 41 53 41 20 4c 4f 43 4b 45 52 } //1 VASA LOCKER
		$a_81_3 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 73 20 61 6e 64 20 73 65 72 76 65 72 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //10 Your computers and servers are encrypted
		$a_81_4 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 68 } //1 @protonmail.ch
		$a_81_5 = {59 4f 55 52 20 50 45 52 53 4f 4e 41 4c 20 49 44 2c 20 41 54 54 41 43 48 20 49 54 3a } //1 YOUR PERSONAL ID, ATTACH IT:
		$a_81_6 = {21 21 21 20 44 41 4e 47 45 52 20 21 21 21 } //10 !!! DANGER !!!
		$a_81_7 = {5f 5f 4e 49 53 54 5f 4b 35 37 31 5f 5f } //10 __NIST_K571__
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*10+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*10+(#a_81_7  & 1)*10) >=44
 
}