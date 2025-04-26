
rule Ransom_Win32_XYLocker_MTB{
	meta:
		description = "Ransom:Win32/XYLocker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 00 69 00 6c 00 65 00 73 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 Files Encrypted
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 20 62 79 20 58 59 20 4c 6f 63 6b 65 72 } //1 encrypted by XY Locker
		$a_01_2 = {68 6f 75 72 73 20 74 6f 20 70 61 79 } //1 hours to pay
		$a_01_3 = {69 6e 20 42 69 74 63 6f 69 6e 20 74 6f 20 74 68 65 20 61 64 72 65 73 73 } //1 in Bitcoin to the adress
		$a_01_4 = {74 68 65 6e 20 41 4c 4c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 67 6f 6e 65 } //1 then ALL your files will be gone
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}