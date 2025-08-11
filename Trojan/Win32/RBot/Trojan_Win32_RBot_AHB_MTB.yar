
rule Trojan_Win32_RBot_AHB_MTB{
	meta:
		description = "Trojan:Win32/RBot.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d bd fb f9 ff ff f3 ab aa be ?? ?? ?? ?? 8d bd fc fe ff ff a5 a5 66 a5 a4 6a 3e 59 33 c0 8d bd 07 ff ff ff f3 ab aa 68 04 01 00 00 } //2
		$a_01_1 = {49 41 4d 4e 4f 54 48 49 4e 47 } //2 IAMNOTHING
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}