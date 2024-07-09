
rule Trojan_Win32_Emotetcrypt_VQ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 [0-02] 8b 0d [0-04] 8a 14 [0-02] 8b 44 [0-02] 30 14 [0-02] 47 3b [0-04] 0f 8c [0-04] 8a [0-04] 8b [0-04] 8a [0-04] 5e 5d 5b 88 [0-02] 88 [0-02] 5f 83 [0-02] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}