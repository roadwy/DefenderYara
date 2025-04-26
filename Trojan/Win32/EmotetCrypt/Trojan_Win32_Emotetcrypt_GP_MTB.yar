
rule Trojan_Win32_Emotetcrypt_GP_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2a 03 c2 99 bb ?? ?? ?? ?? f7 fb 33 c0 40 2b c6 0f af 05 ?? ?? ?? ?? 47 0f af fe 2b c7 03 c1 2b 05 ?? ?? ?? ?? 03 d5 6b c0 05 8a 0c 10 8b 44 24 24 30 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}