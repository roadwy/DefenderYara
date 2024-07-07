
rule Ransom_Win32_Molock_MAK_MTB{
	meta:
		description = "Ransom:Win32/Molock.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 64 69 73 6b 20 68 61 76 65 20 61 20 6c 6f 63 6b 21 50 6c 65 61 73 65 20 69 6e 70 75 74 20 74 68 65 20 75 6e 6c 6f 63 6b 20 70 61 73 73 77 6f 72 64 21 } //Your disk have a lock!Please input the unlock password!  10
		$a_80_1 = {5c 70 68 79 73 69 63 61 6c 64 72 69 76 65 30 } //\physicaldrive0  1
		$a_80_2 = {70 6f 72 74 3a } //port:  1
		$a_80_3 = {69 70 20 2f 20 68 6f 73 74 3a } //ip / host:  1
		$a_80_4 = {6d 61 69 6c 74 6f 3a } //mailto:  1
		$a_80_5 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //shell\open\command  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=15
 
}