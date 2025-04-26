
rule Trojan_Win32_CryptInject_DSKP_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DSKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d e9 2b 00 00 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 c1 e9 2b 00 00 a1 ?? ?? ?? ?? a3 } //2
		$a_00_1 = {8b ca 2b ce 83 e9 4b 8b f9 6b ff 53 81 c5 2c c6 14 01 03 d2 2b d7 8b 7c 24 18 89 2b } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2) >=2
 
}