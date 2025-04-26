
rule Trojan_Win32_Emotetcrypt_VH_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 01 30 07 8b 45 ?? 3b 75 ?? 0f 8c 90 0a 19 00 0f b6 cb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VH_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 33 d2 f7 f5 [0-19] 8b 44 [0-02] 8b 54 [0-02] 8a 0c [0-02] 32 0c [0-02] 40 83 6c [0-02] 01 88 48 [0-02] 89 44 [0-02] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}