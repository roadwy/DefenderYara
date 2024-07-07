
rule Trojan_Win64_DllInject_MB_MTB{
	meta:
		description = "Trojan:Win64/DllInject.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 8d 2c 09 48 81 ea 00 00 01 00 49 ff c1 48 89 d1 66 81 e2 ff 03 48 c1 f9 0a 66 81 ea 00 24 66 81 e9 00 28 66 89 54 28 02 66 89 0c 28 49 ff c1 e9 } //5
		$a_01_1 = {4c 6f 63 6b 44 6f 77 6e 50 72 6f 74 65 63 74 50 72 6f 63 65 73 73 42 79 49 64 } //1 LockDownProtectProcessById
		$a_01_2 = {4e 69 6d 4d 61 69 6e } //1 NimMain
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}