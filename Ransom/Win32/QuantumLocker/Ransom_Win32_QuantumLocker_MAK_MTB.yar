
rule Ransom_Win32_QuantumLocker_MAK_MTB{
	meta:
		description = "Ransom:Win32/QuantumLocker.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //1 expand 32-byte k
		$a_81_1 = {25 43 4c 49 45 4e 54 5f 49 44 25 } //1 %CLIENT_ID%
		$a_81_2 = {46 69 6c 65 73 20 6f 6e 20 74 68 65 20 77 6f 72 6b 73 74 61 74 69 6f 6e 73 20 69 6e 20 79 6f 75 72 20 6e 65 74 77 6f 72 6b 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Files on the workstations in your network were encrypted
		$a_81_3 = {41 66 74 65 72 20 61 20 70 61 79 6d 65 6e 74 20 79 6f 75 27 6c 6c 20 67 65 74 20 6e 65 74 77 6f 72 6b 20 64 65 63 72 79 70 74 69 6f 6e } //1 After a payment you'll get network decryption
		$a_81_4 = {2e 6f 6e 69 6f 6e 2f 3f 63 69 64 3d 25 43 4c 49 45 4e 54 5f 49 44 25 } //1 .onion/?cid=%CLIENT_ID%
		$a_81_5 = {51 75 61 6e 74 75 6d 20 4c 6f 63 6b 65 72 } //1 Quantum Locker
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}