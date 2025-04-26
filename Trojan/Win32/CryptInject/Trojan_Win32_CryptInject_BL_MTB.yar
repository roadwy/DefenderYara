
rule Trojan_Win32_CryptInject_BL_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 81 ff 9b 0a 00 00 75 } //1
		$a_02_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 81 3d ?? ?? ?? ?? ac 10 00 00 56 a3 ?? ?? ?? ?? 8b f0 75 ?? ff 15 ?? ?? ?? ?? 8b 4d ?? 8b c6 c1 e8 10 33 cd 25 ff 7f 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}