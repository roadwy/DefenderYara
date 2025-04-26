
rule Trojan_Win32_NukeSped_MA_MTB{
	meta:
		description = "Trojan:Win32/NukeSped.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a c2 b3 88 fe c0 f6 ac 24 ?? ?? ?? ?? f6 eb 88 44 14 0c 42 81 fa ?? ?? ?? ?? 7c } //5
		$a_01_1 = {8a 54 0c 10 8a 1c 38 32 da 03 ce 88 1c 38 81 e1 ff 00 00 00 40 3b c5 7c } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}