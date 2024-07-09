
rule Trojan_Win32_Emotetcrypt_VV_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 8a [0-02] 8b 44 [0-02] 30 14 [0-01] 8b 44 [0-02] 45 3b [0-01] 7c [0-05] 8b [0-03] 8a [0-03] 5f [0-02] 88 [0-01] 88 [0-02] 5d 59 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}