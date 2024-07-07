
rule Ransom_Win32_SpyroCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/SpyroCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 53 70 79 72 6f } //1 .Spyro
		$a_01_1 = {42 6c 61 63 6b 53 70 79 72 6f } //1 BlackSpyro
		$a_01_2 = {66 75 63 6b 79 6f 75 66 75 63 6b 79 6f 75 } //1 fuckyoufuckyou
		$a_01_3 = {44 00 65 00 63 00 72 00 79 00 70 00 74 00 2d 00 69 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //1 Decrypt-info.txt
		$a_01_4 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 3d 64 69 73 61 62 6c 65 } //1 netsh firewall set opmode mode=disable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}