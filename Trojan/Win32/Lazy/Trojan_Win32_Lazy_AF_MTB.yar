
rule Trojan_Win32_Lazy_AF_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 85 4c e8 ff ff 33 c0 88 85 98 e8 ff ff 33 c9 88 8d 97 e8 ff ff 0f b6 95 98 e8 ff ff 52 0f b6 85 97 e8 ff ff 50 0f b6 8d 66 e8 ff ff 51 8d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}