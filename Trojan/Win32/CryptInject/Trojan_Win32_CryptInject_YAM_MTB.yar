
rule Trojan_Win32_CryptInject_YAM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0b c0 c8 03 32 87 ?? ?? ?? ?? 88 04 0b 8d 47 01 bf 0d 00 00 00 99 f7 ff 41 8b fa 3b ce } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}