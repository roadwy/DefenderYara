
rule Trojan_Win64_RevShellz_A_MTB{
	meta:
		description = "Trojan:Win64/RevShellz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 06 4e 0f be ac 20 60 39 24 00 41 8d 4d 01 4c 8b 4d 9f 4c 2b ce 48 63 c1 49 3b c1 ?? ?? ?? ?? ?? ?? 48 89 7d af 48 89 75 df 8b c7 83 f9 04 0f 94 c0 ff c0 44 8b f0 44 8b c0 4c 89 54 24 20 } //1
		$a_81_1 = {70 61 79 6c 6f 61 64 } //1 payload
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}