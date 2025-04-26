
rule Trojan_Win32_VBKrypt_AVS_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {44 65 6d 61 72 6b 61 74 69 6f 6e 73 6c 69 6e 6a 65 6e 73 37 } //Demarkationslinjens7  2
		$a_80_1 = {6e 65 72 76 65 6d 65 64 69 63 69 6e 73 } //nervemedicins  2
		$a_80_2 = {6b 6e 6f 70 73 6b 79 64 65 } //knopskyde  2
		$a_80_3 = {73 74 6e 69 6e 67 73 73 74 72 75 6b 74 75 72 65 72 } //stningsstrukturer  2
		$a_80_4 = {43 65 6c 6c 65 73 6c 69 6d 73 } //Celleslims  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=10
 
}