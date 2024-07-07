
rule Ransom_Win32_VoidCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/VoidCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b } //1 fuck
		$a_01_1 = {5c 00 21 00 49 00 4e 00 46 00 4f 00 2e 00 48 00 54 00 41 00 } //1 \!INFO.HTA
		$a_01_2 = {70 00 65 00 61 00 63 00 65 00 34 00 39 00 31 00 40 00 74 00 75 00 74 00 61 00 2e 00 69 00 6f 00 } //1 peace491@tuta.io
		$a_01_3 = {2e 50 65 61 63 65 } //1 .Peace
		$a_01_4 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //1 bcdedit /set {default} recoveryenabled no
		$a_01_5 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 3d 64 69 73 61 62 6c 65 } //1 netsh firewall set opmode mode=disable
		$a_01_6 = {21 21 21 20 59 6f 75 72 20 46 69 6c 65 73 20 48 61 73 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 20 21 21 21 } //1 !!! Your Files Has Been Encrypted !!!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}