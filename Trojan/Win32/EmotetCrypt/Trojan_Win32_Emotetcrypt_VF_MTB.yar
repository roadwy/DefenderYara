
rule Trojan_Win32_Emotetcrypt_VF_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d2 8a 0c ?? 8b 45 ?? 30 ?? 3b 5d ?? 7c 90 0a 28 00 03 [0-07] f7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VF_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 33 d2 f7 35 [0-04] 03 d5 8a 04 [0-02] 8a 54 [0-02] 02 c2 8b 54 [0-02] 32 04 [0-02] 43 88 43 [0-02] 8b 44 [0-02] 48 89 44 [0-02] 75 [0-02] 5f 5e 5d 5b 83 c4 0c c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}