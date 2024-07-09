
rule Trojan_Win32_Emotetcrypt_VT_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d2 8a [0-02] 8b 44 [0-02] 30 4c [0-02] 3b 74 [0-02] 7c [0-01] 8b [0-03] 8a [0-03] 8a [0-03] 5f 5d 5b 88 [0-01] 88 [0-02] 5e 59 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}