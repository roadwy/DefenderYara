
rule Trojan_Win32_Lazy_VGZ_MTB{
	meta:
		description = "Trojan:Win32/Lazy.VGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 c9 74 25 fe c0 0f b6 c0 0f b6 1c 07 00 da 0f b6 d2 8a 3c 17 88 3c 07 88 1c 17 00 fb 0f b6 db 8a 1c 1f 30 1e 46 49 eb d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}