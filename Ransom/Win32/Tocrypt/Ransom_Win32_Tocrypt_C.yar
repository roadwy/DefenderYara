
rule Ransom_Win32_Tocrypt_C{
	meta:
		description = "Ransom:Win32/Tocrypt.C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {84 c0 74 0f 90 09 2c 00 01 00 00 00 c7 44 ?? ?? 00 00 00 00 c7 04 ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 0e 00 00 00 e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 0f c7 85 ?? ?? ?? ?? 01 00 00 00 e9 } //4
		$a_00_1 = {5c 54 4f 58 20 52 41 4e 53 4f 4d 2e 68 74 6d 6c } //2 \TOX RANSOM.html
		$a_00_2 = {5c 74 6f 78 2e 6c 6f 67 } //1 \tox.log
		$a_00_3 = {5c 74 6f 78 5f 74 6f 72 5c } //1 \tox_tor\
		$a_00_4 = {2e 74 6f 78 63 72 79 70 74 } //1 .toxcrypt
		$a_00_5 = {5c 74 6f 78 2e 64 6f 6e 65 2e 6c 6f 67 } //1 \tox.done.log
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=10
 
}