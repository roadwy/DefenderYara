
rule Trojan_Win32_VBKrypt_AT_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 0c 24 eb 90 0a 1f 00 8b 0f eb [0-1f] 89 0c 24 eb [0-1f] 31 34 24 eb [0-1f] 59 eb [0-1f] 83 c2 04 eb [0-1f] 83 d7 04 eb [0-1f] 81 fa ?? ?? 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}