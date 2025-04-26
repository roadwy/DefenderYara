
rule Trojan_Win32_Neoreblamy_NMD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 1f 0f b6 c8 8b d1 88 85 53 fe ff ff c1 ea 03 83 e1 07 b0 01 d2 e0 08 44 15 dc 8a 95 53 fe ff ff 8a 07 3c 5d } //2
		$a_03_1 = {99 2b c2 8b c8 d1 f9 8b 85 ?? ?? ff ff 40 0f af 85 ?? ?? ff ff 99 2b c2 d1 f8 03 c8 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}