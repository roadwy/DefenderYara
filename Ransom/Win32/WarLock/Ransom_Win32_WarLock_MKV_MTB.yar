
rule Ransom_Win32_WarLock_MKV_MTB{
	meta:
		description = "Ransom:Win32/WarLock.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_81_0 = {57 65 20 61 72 65 20 5b 57 61 72 6c 6f 63 6b 20 47 72 6f 75 70 5d } //2 We are [Warlock Group]
		$a_81_1 = {59 6f 75 72 20 73 79 73 74 65 6d 73 20 68 61 76 65 20 62 65 65 6e 20 6c 6f 63 6b 65 64 } //1 Your systems have been locked
		$a_81_2 = {50 65 72 6d 61 6e 65 6e 74 20 44 61 74 61 20 4c 6f 73 73 } //1 Permanent Data Loss
		$a_81_3 = {3d 3d 3d 3d 3e 49 66 20 59 6f 75 20 52 65 66 75 73 65 20 74 6f 20 50 61 79 } //1 ====>If You Refuse to Pay
		$a_81_4 = {64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //1 decryption key
		$a_81_5 = {57 61 72 6c 6f 63 6b 20 71 54 6f 78 20 49 44 } //1 Warlock qTox ID
		$a_81_6 = {48 6f 77 20 74 6f 20 64 65 63 72 79 70 74 20 6d 79 20 64 61 74 61 2e 74 78 74 } //1 How to decrypt my data.txt
		$a_81_7 = {49 6d 70 6f 72 74 61 6e 74 21 21 21 2e 70 64 66 } //1 Important!!!.pdf
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=7
 
}