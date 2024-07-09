
rule Trojan_Win32_GandCrypt_GJ_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 81 ec 10 08 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 f8 89 95 f0 f7 ff ff 89 8d f4 f7 ff ff 81 3d ?? ?? ?? ?? a3 09 00 00 75 ?? 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 } //1
		$a_02_1 = {55 8b ec 51 a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 8b 0d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}