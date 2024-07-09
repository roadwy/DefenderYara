
rule Trojan_Win32_CryptInject_AB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 56 a3 ?? ?? ?? ?? 0f b7 35 ?? ?? ?? ?? 81 e6 ff 7f 00 00 81 3d ?? ?? ?? ?? e7 08 00 00 } //1
		$a_03_1 = {81 fb 85 02 00 00 75 ?? 56 56 56 56 56 ff 15 ?? ?? ?? ?? 56 56 56 56 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 2f 81 fb 91 05 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}