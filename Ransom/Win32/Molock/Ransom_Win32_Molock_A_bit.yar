
rule Ransom_Win32_Molock_A_bit{
	meta:
		description = "Ransom:Win32/Molock.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 06 00 00 00 8b 5d f8 e8 90 01 04 53 68 01 00 00 00 68 04 00 00 00 68 1a 02 00 c0 b8 0a 00 00 00 e8 90 01 04 39 65 f4 74 0d 68 06 00 00 00 e8 90 00 } //1
		$a_01_1 = {4e 74 52 61 69 73 65 48 61 72 64 45 72 72 6f 72 } //1 NtRaiseHardError
		$a_01_2 = {5c 5c 70 68 79 73 69 63 61 6c 64 72 69 76 65 30 } //1 \\physicaldrive0
		$a_01_3 = {59 6f 75 72 20 64 69 73 6b 20 68 61 76 65 20 61 20 6c 6f 63 6b 21 50 6c 65 61 73 65 20 69 6e 70 75 74 20 74 68 65 20 75 6e 6c 6f 63 6b 20 70 61 73 73 77 6f 72 64 21 } //1 Your disk have a lock!Please input the unlock password!
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}