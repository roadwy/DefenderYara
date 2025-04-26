
rule Trojan_Win32_CryptInject_OIU_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.OIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 44 18 ff 24 0f 8b 55 f0 8a 54 32 ff 80 e2 0f 32 c2 88 45 f7 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d f7 02 d1 88 54 18 ff 46 8b 45 f0 e8 ?? ?? ?? ?? 3b f0 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}