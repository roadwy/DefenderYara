
rule Trojan_Win32_Emotetcrypt_VO_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 [0-01] a1 [0-04] 8a 0c [0-01] 8b 44 [0-02] 30 0c [0-06] 3b [0-03] 0f 8c [0-04] 8b [0-03] 8a [0-03] 8a [0-03] 5f [0-02] 88 [0-01] 88 [0-02] 5b 59 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}