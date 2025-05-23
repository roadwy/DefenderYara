
rule Trojan_Win32_CryptInject_A_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 00 81 6d fc ?? ?? ?? ?? 81 45 fc ?? ?? ?? ?? c1 e8 ?? 81 6d fc ?? ?? ?? ?? c1 e0 ?? 81 45 fc ?? ?? ?? ?? b8 ?? ?? ?? ?? 81 6d fc ?? ?? ?? ?? 35 ?? ?? ?? ?? 81 45 fc ?? ?? ?? ?? c1 eb ?? 81 45 fc ?? ?? ?? ?? d1 e3 d1 e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CryptInject_A_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 82 ?? ?? ?? ?? 03 c1 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 03 c1 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 87 ?? ?? ?? ?? 03 c1 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 83 ?? ?? ?? ?? 03 c1 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 83 c1 05 81 f9 00 66 0d 00 72 } //1
		$a_81_1 = {72 75 6e 44 6c 6c 46 72 6f 6d 4d 65 6d 6f 72 79 } //1 runDllFromMemory
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}