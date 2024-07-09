
rule Trojan_Win32_SpyEyes_DSK_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b da 83 e3 03 03 f8 8b 5c 9e 04 03 da 33 fb 2b cf ff 4d 08 75 } //2
		$a_02_1 = {8b 11 2b 55 ?? 8b 45 0c 03 45 f8 89 10 8b 4d ?? 81 e1 ff 00 00 00 f7 d1 88 4d e8 eb } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}