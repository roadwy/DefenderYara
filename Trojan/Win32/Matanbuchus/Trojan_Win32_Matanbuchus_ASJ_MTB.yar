
rule Trojan_Win32_Matanbuchus_ASJ_MTB{
	meta:
		description = "Trojan:Win32/Matanbuchus.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {f7 d2 2b c2 03 c8 } //2
		$a_01_1 = {f7 d1 f7 d2 89 0d } //2
		$a_01_2 = {2b c1 f7 d0 0f b7 15 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}