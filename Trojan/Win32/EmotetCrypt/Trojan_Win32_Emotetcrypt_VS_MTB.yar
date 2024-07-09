
rule Trojan_Win32_Emotetcrypt_VS_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 [0-02] 8b 0d [0-04] 8b 44 [0-04] 8a 14 [0-02] 30 14 [0-02] 8b 44 [0-02] 45 3b [0-02] 7c 87 8b [0-04] 8a [0-04] 5f 88 [0-02] 5b 5e 88 [0-02] 5d 59 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}