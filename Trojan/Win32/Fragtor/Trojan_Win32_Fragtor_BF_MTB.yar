
rule Trojan_Win32_Fragtor_BF_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 24 0b 8b 14 85 ?? ?? ?? 00 0f b6 33 31 f1 88 4c 24 0b 83 fa 01 77 } //3
		$a_01_1 = {0f b6 4c 24 0b 32 4c 13 ff 88 4c 24 0b 8b 4c 24 0c 01 d1 89 4c 24 0c 89 f1 80 f9 4d 75 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}