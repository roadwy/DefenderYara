
rule Trojan_Win32_Emotetcrypt_SA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b d0 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 8b 45 14 0f b6 14 10 33 ca } //1
		$a_03_1 = {03 45 0c 88 0c 10 e9 90 09 15 00 0f af 05 ?? ?? ?? ?? 2b d0 a1 ?? ?? ?? ?? 0f af 05 } //1
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}