
rule Trojan_Win32_VBKrypt_AF_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 fb 00 66 81 [0-ff] ff d2 [0-ff] ff 37 [0-2f] 5b [0-2f] 31 f3 [0-2f] 01 1c 10 [0-2f] 83 c2 04 [0-4f] 81 fa ?? ?? 00 00 0f 85 ?? ff ff ff [0-4f] ff d0 } //1
		$a_02_1 = {8b 14 0a f7 c7 [0-ff] ff d2 [0-ff] ff 37 [0-2f] 5b [0-2f] 31 f3 [0-3f] 8f 04 10 [0-2f] 83 c2 04 [0-4f] 81 fa ?? ?? 00 00 0f 85 ?? ?? ff ff [0-4f] ff d0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}