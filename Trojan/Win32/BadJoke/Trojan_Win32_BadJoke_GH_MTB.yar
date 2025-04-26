
rule Trojan_Win32_BadJoke_GH_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 73 74 72 75 63 74 53 61 66 65 74 79 2e 70 64 62 } //1 DestructSafety.pdb
		$a_81_1 = {54 68 65 20 73 6f 66 74 77 61 72 65 20 79 6f 75 20 6a 75 73 74 20 65 78 65 63 75 74 65 64 20 69 73 20 63 6f 6e 73 69 64 65 72 65 64 20 6d 61 6c 77 61 72 65 2e } //1 The software you just executed is considered malware.
		$a_81_2 = {54 68 69 73 20 6d 61 6c 77 61 72 65 20 77 69 6c 6c 20 68 61 72 6d 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 61 6e 64 20 6d 61 6b 65 73 20 69 74 20 75 6e 75 73 61 62 6c 65 2e } //1 This malware will harm your computer and makes it unusable.
		$a_81_3 = {49 66 20 79 6f 75 20 61 72 65 20 73 65 65 69 6e 67 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 77 69 74 68 6f 75 74 20 6b 6e 6f 77 69 6e 67 20 77 68 61 74 20 79 6f 75 20 6a 75 73 74 20 65 78 65 63 75 74 65 64 2c } //1 If you are seeing this message without knowing what you just executed,
		$a_81_4 = {70 72 65 73 73 20 59 65 73 20 74 6f 20 73 74 61 72 74 20 69 74 2e 20 44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 65 78 65 63 75 74 65 20 74 68 69 73 20 6d 61 6c 77 61 72 65 2c 20 72 65 73 75 6c 74 69 6e 67 20 69 6e 20 61 6e 20 75 6e 75 73 61 62 6c 65 20 6d 61 63 68 69 6e 65 3f } //1 press Yes to start it. Do you want to execute this malware, resulting in an unusable machine?
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}