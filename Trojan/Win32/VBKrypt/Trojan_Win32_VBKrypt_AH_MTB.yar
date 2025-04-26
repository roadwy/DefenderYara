
rule Trojan_Win32_VBKrypt_AH_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 37 81 fa ?? ?? ?? ?? 66 [0-1f] 59 [0-1f] e8 ?? ?? 00 00 [0-6f] 89 0b [0-1f] 83 c2 04 [0-1f] 83 c7 04 [0-6f] e9 ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}