
rule Trojan_Win32_Alureon_EN{
	meta:
		description = "Trojan:Win32/Alureon.EN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 53 43 52 49 50 54 5f 53 49 47 4e 41 54 55 52 45 5f 43 48 45 43 4b 5d } //1 [SCRIPT_SIGNATURE_CHECK]
		$a_01_1 = {5b 6b 69 74 5f 68 61 73 68 5f 65 6e 64 5d } //1 [kit_hash_end]
		$a_01_2 = {5b 63 6d 64 5f 64 6c 6c 5f 68 61 73 68 5f 65 6e 64 5d } //1 [cmd_dll_hash_end]
		$a_03_3 = {8a d0 80 c2 51 30 90 90 ?? ?? ?? ?? 83 c0 01 3d 00 01 00 00 72 eb } //2
		$a_03_4 = {8a c8 80 c1 51 30 88 ?? ?? ?? ?? 83 c0 01 83 f8 20 72 ed } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2) >=3
 
}