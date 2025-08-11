
rule Trojan_Win64_DarkMoon_GVA_MTB{
	meta:
		description = "Trojan:Win64/DarkMoon.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {32 c3 48 8d 3f 48 8d 3f 48 8d 3f 90 13 2a c3 48 8d 3f 48 8d 3f 48 8d 3f 90 13 48 8d 3f 32 c3 48 8d 3f 2a c3 90 13 48 8d 3f 48 8d 3f c0 c8 fe 48 8d 3f 90 13 48 8d 3f 48 8d 3f aa 48 83 e9 01 } //2
		$a_01_1 = {ac 48 8d 3f 48 8d 3f } //1
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}