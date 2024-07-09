
rule Trojan_Win32_Emotetcrypt_VW_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 8b 15 [0-04] 8a 04 10 90 17 04 01 01 01 01 31 32 30 33 [0-0a] 7c ?? 8a ?? ?? ?? 8b ?? ?? ?? 8a ?? ?? ?? 5f [0-02] 88 [0-02] 88 [0-02] 5d 59 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}