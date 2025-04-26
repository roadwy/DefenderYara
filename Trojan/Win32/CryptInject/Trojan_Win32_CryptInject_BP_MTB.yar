
rule Trojan_Win32_CryptInject_BP_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 8b 75 f8 03 75 f0 68 5c 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 8b 55 f8 03 55 f0 8b 45 fc 8b 4d f4 8a 0c 31 88 0c 10 8b 55 f8 83 c2 01 89 55 f8 eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CryptInject_BP_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BP!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 3e 00 20 00 6e 00 75 00 6c 00 } //1 ping 127.0.0.1 > nul
		$a_01_1 = {65 00 63 00 68 00 6f 00 20 00 6a 00 20 00 7c 00 20 00 64 00 65 00 6c 00 20 00 54 00 72 00 69 00 6e 00 69 00 74 00 79 00 2e 00 62 00 61 00 74 00 } //1 echo j | del Trinity.bat
		$a_01_2 = {54 72 69 6e 69 74 79 4f 62 66 75 73 63 61 74 6f 72 } //1 TrinityObfuscator
		$a_01_3 = {49 4c 6f 76 65 54 68 65 52 65 61 6c 47 69 74 68 73 } //1 ILoveTheRealGiths
		$a_01_4 = {66 69 6c 65 5f 65 78 65 } //1 file_exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}