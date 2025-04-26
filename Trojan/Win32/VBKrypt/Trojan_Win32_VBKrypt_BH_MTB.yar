
rule Trojan_Win32_VBKrypt_BH_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e1 00 8b 99 [0-1f] 53 [0-1f] 81 34 24 [0-1f] 8f 04 08 [0-1f] 41 [0-2f] 83 c1 f8 7d [0-1f] ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}