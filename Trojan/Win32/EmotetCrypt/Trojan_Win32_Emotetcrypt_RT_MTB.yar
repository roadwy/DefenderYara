
rule Trojan_Win32_Emotetcrypt_RT_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b c0 13 2b c8 0f b6 44 8d 90 01 01 30 43 90 01 01 b8 cb 6b 28 af 8b 4d 90 01 01 03 cb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}