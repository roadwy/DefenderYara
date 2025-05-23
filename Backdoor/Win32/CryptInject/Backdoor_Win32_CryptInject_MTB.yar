
rule Backdoor_Win32_CryptInject_MTB{
	meta:
		description = "Backdoor:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 ZwUnmapViewOfSection
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_2 = {57 58 59 5a 61 62 63 42 41 43 44 4c 4d 4e 4f 50 51 45 46 47 48 49 4a 4b 52 53 54 55 56 66 67 68 69 64 65 70 71 72 73 74 6a 6b 6c 6d 6e 6f 75 76 77 78 79 7a 34 35 36 37 38 39 30 31 32 33 2b 2f } //1 WXYZabcBACDLMNOPQEFGHIJKRSTUVfghidepqrstjklmnouvwxyz4567890123+/
		$a_01_3 = {47 49 6c 51 57 57 4d 57 57 57 57 61 57 57 57 57 2f 2f 32 57 57 4c 69 57 57 57 57 57 57 57 57 57 51 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 69 57 57 57 57 57 38 } //1 GIlQWWMWWWWaWWWW//2WWLiWWWWWWWWWQWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWiWWWWW8
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}