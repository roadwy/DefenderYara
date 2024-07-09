
rule Trojan_Win32_Emotetcrypt_RMA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e1 0f 0f b6 8c 8d ?? ?? ?? ?? 30 48 ?? 8b 4d ?? 03 c8 83 e1 0f 0f b6 8c 8d ?? ?? ?? ?? 30 48 ?? 83 c0 06 81 fa 00 34 02 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}