
rule Trojan_Win32_Graftor_AGF_MTB{
	meta:
		description = "Trojan:Win32/Graftor.AGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 6a 22 55 ff 15 ?? ?? ?? ?? 8b 54 24 3c 8d 4c 24 60 51 52 ff 15 ?? ?? ?? ?? 8d 44 24 60 8d 4c 24 20 50 e8 ?? ?? ?? ?? 68 c8 d9 40 00 8d 4c 24 24 } //2
		$a_03_1 = {2a c1 8d 4c 24 08 fe c0 88 44 24 0c 8b 44 24 0c 50 56 e8 ?? ?? ?? ?? 8b 44 24 28 46 4f 3b 70 f8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}