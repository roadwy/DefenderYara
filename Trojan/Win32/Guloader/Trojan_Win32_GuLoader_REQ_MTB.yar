
rule Trojan_Win32_GuLoader_REQ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {75 6e 65 6e 63 72 6f 61 63 68 65 64 } //1 unencroached
		$a_81_1 = {64 65 61 6d 69 6e 69 7a 65 64 20 74 72 69 6d 65 74 68 79 6c 61 6d 69 6e 65 } //1 deaminized trimethylamine
		$a_81_2 = {74 69 6c 67 6f 64 65 73 61 61 20 6c 61 6e 64 76 73 65 6e 73 72 65 74 73 6b 65 6e 64 65 6c 73 65 72 6e 65 2e 65 78 65 } //1 tilgodesaa landvsensretskendelserne.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}