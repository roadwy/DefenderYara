
rule Ransom_Win32_LockScreen_X{
	meta:
		description = "Ransom:Win32/LockScreen.X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {54 6f 20 75 6e 6c 6f 63 6b 20 74 68 65 20 6e 65 65 64 20 66 6f 72 20 32 20 68 6f 75 72 73 2c 20 66 6f 6c 6c 6f 77 20 74 68 65 73 65 20 73 74 65 70 73 } //1 To unlock the need for 2 hours, follow these steps
		$a_00_1 = {49 6e 20 63 61 73 65 20 6f 66 20 72 65 66 75 73 61 6c 20 74 6f 20 70 61 79 2c 20 77 69 6c 6c 20 62 65 67 69 6e 20 72 65 6d 6f 76 69 6e 67 } //1 In case of refusal to pay, will begin removing
		$a_03_2 = {b9 af 00 00 00 ba 97 00 00 00 e8 ?? ?? ?? ?? 33 c9 ba b3 00 00 00 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}