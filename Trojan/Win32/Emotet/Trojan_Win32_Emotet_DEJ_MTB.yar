
rule Trojan_Win32_Emotet_DEJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 14 (45|83 c0 f0) 83 c5 01 c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8d 48 0c 8a 54 14 1c 30 55 ff } //1
		$a_81_1 = {6e 66 66 6b 44 4c 66 6f 45 57 44 6d 52 33 46 43 61 66 68 41 72 66 67 64 6a 79 36 6b 74 67 48 4f 4d 41 57 } //1 nffkDLfoEWDmR3FCafhArfgdjy6ktgHOMAW
		$a_81_2 = {51 64 7a 74 38 4c 6d 49 50 51 70 6d 73 77 64 41 4c 64 50 4c 4e 46 51 65 4a 4f 44 70 74 59 36 43 4d 5a 4c } //1 Qdzt8LmIPQpmswdALdPLNFQeJODptY6CMZL
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}