
rule Trojan_Win32_Vidar_GVF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 34 0b 48 89 d7 48 c1 ff 08 29 fe 40 88 34 19 48 ff c3 48 39 d8 7f e7 } //2
		$a_01_1 = {0f b6 34 0b 31 d6 31 de 40 88 34 19 48 ff c3 48 39 d8 7f ec } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}