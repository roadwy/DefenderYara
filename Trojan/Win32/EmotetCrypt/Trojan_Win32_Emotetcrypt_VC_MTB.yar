
rule Trojan_Win32_Emotetcrypt_VC_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 8a 04 38 30 ?? 8b 45 ?? 8b 5d ?? 3b 75 ?? 7c 90 0a 23 00 03 ?? ?? ?? ?? ?? ?? 99 f7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VC_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 33 d2 f7 35 [0-04] 03 54 24 [0-02] 8a 04 [0-02] 8b 54 24 [0-02] 02 c3 32 04 [0-02] 45 88 45 ff 8b 44 24 [0-02] 48 89 6c 24 24 89 44 24 10 75 [0-02] 5f 5e 5d 5b 83 c4 0c c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}