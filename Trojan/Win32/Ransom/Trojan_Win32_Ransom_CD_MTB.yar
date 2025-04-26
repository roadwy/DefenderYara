
rule Trojan_Win32_Ransom_CD_MTB{
	meta:
		description = "Trojan:Win32/Ransom.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 1c 01 33 1c 11 75 0a 83 c1 04 78 f3 } //1
		$a_00_1 = {8a 5c 31 06 f6 c3 80 75 e1 32 1c 11 f6 c3 80 75 d9 80 e3 df 75 d0 49 75 e7 } //1
		$a_81_2 = {52 61 6e 73 6f 6d 77 61 72 65 20 44 65 6d 6f } //1 Ransomware Demo
		$a_81_3 = {44 65 63 72 79 70 74 20 2a 2e 65 6e 63 72 79 20 74 6f 20 6f 72 69 67 69 6e 61 6c 20 66 69 6c 65 20 65 78 74 65 6e 73 69 6f 6e 2e } //1 Decrypt *.encry to original file extension.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}