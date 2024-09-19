
rule Trojan_Win32_CryptInject_BBA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f2 2b 4d fa 89 55 e7 89 45 e7 8b 4d e8 81 c3 a8 a2 00 00 8b 35 ?? ?? ?? ?? 89 d9 89 1d ?? ?? ?? ?? 89 c6 66 8b 4d e3 8b 5d fd 33 55 fa 8b 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}