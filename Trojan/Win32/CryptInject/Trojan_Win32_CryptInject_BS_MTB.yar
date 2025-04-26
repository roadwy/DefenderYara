
rule Trojan_Win32_CryptInject_BS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 02 83 45 [0-03] 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 ?? 6a 00 e8 ?? ?? ?? ?? 2b d8 01 5d ?? 8b 45 ?? 3b 45 ?? 72 90 0a 40 00 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CryptInject_BS_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 32 d0 13 00 7c ?? 81 05 ?? ?? ?? ?? c1 3b 0f 00 } //1
		$a_02_1 = {81 ec 00 04 00 00 53 56 57 8b fa 33 f6 8b d9 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 8d 9b 00 00 00 00 e8 ?? ?? ?? ?? 30 04 1e 81 ff 79 06 00 00 75 ?? 8d 44 24 10 50 6a 00 ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}