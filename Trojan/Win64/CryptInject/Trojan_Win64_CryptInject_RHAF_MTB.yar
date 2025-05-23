
rule Trojan_Win64_CryptInject_RHAF_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.RHAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 64 86 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0b 00 00 36 01 00 00 06 02 00 00 00 00 00 24 59 } //2
		$a_00_1 = {4b 00 65 00 79 00 20 00 47 00 75 00 61 00 72 00 64 00 } //1 Key Guard
		$a_01_2 = {68 6f 73 74 20 75 6e 72 65 61 63 68 61 62 6c 65 } //1 host unreachable
		$a_01_3 = {43 72 65 61 74 65 46 69 6c 65 32 } //1 CreateFile2
		$a_02_4 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 4d 00 69 00 6e 00 64 00 73 00 6f 00 66 00 74 00 20 00 63 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1
		$a_02_5 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 ?? ?? 4c 00 73 00 61 00 6c 00 73 00 2e 00 64 00 6c 00 6c 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=7
 
}