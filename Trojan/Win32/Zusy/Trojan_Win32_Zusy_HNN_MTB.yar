
rule Trojan_Win32_Zusy_HNN_MTB{
	meta:
		description = "Trojan:Win32/Zusy.HNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d9 8b c7 8d 8d ?? ?? ?? ?? 99 03 cf f7 fe 47 8a 82 ?? ?? ?? ?? 32 04 0b 88 01 } //2
		$a_01_1 = {c1 f9 04 c0 e0 02 0a c8 88 0f } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}