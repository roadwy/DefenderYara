
rule Trojan_Win32_CryptInject_FDSD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.FDSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {c6 85 53 fa ?? ?? ac c6 85 54 fa ?? ?? 24 c6 85 55 fa ?? ?? 64 c6 85 56 fa ?? ?? fc c6 85 57 fa ?? ?? ?? c6 85 58 fa ?? ?? ?? c6 85 59 fa ?? ?? 81 c6 85 5a fa ?? ?? ec c6 85 5b fa ?? ?? 1c c6 85 5c fa ?? ?? 04 c6 85 5d fa ?? ?? 00 c6 85 5e fa ?? ?? 00 c6 85 5f fa ?? ?? 8b c6 85 60 fa ?? ?? 8d c6 85 61 fa ?? ?? a4 } //1
		$a_01_1 = {3e c7 43 30 69 00 00 00 eb f6 74 f4 83 c0 78 c1 e0 05 09 d1 85 f3 74 24 83 e3 10 8d 53 c0 c1 eb 69 c1 ee 58 7c da } //1
		$a_02_2 = {8b 45 98 83 e8 20 83 e0 11 33 85 fc f9 ?? ?? 66 89 85 14 fa ?? ?? 8b 4d dc 83 c1 09 33 8d 68 ff ff ff 0b 4d c4 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}