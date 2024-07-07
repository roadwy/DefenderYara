
rule Trojan_Win32_Redline_BP_MTB{
	meta:
		description = "Trojan:Win32/Redline.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d0 0f b6 00 32 45 ef 89 c3 0f b6 4d ef 8b 55 f0 8b 45 0c 01 d0 8d 14 0b 88 10 8b 55 f0 8b 45 0c 01 d0 0f b6 10 0f b6 5d ef 8b 4d f0 8b 45 0c 01 c8 29 da 88 10 83 45 f0 01 8b 45 f0 3b 45 10 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}