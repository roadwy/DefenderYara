
rule Trojan_Win32_Emotetcrypt_VZ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 fa 88 54 ?? ?? 0f b6 14 ?? 88 14 ?? 88 04 ?? 0f b6 14 ?? 0f b6 04 ?? 03 c2 99 f7 fb 0f b6 ?? 0f b6 14 ?? 90 17 04 01 01 01 01 30 31 32 33 ?? ?? 83 6c ?? ?? 01 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}