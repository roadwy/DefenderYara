
rule Trojan_Win32_Lazy_ALZ_MTB{
	meta:
		description = "Trojan:Win32/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 17 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 fb 80 eb e8 01 f4 89 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Lazy_ALZ_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 68 00 02 00 00 8d 85 e4 fd ff ff 50 e8 ?? ?? ?? ?? 83 c4 28 8d 86 08 04 00 00 8d 4e 08 6a 00 50 68 ff 03 00 00 51 6a fd 8d 85 e4 fd ff ff 50 6a 00 ff 37 e8 } //2
		$a_01_1 = {6a 00 8d 86 08 04 00 00 50 68 ff 03 00 00 8d 46 08 50 6a fd 8d 85 e4 fd ff ff 50 6a 00 ff 37 e8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}