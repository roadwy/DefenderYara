
rule Trojan_Win32_XWorm_BAF_MTB{
	meta:
		description = "Trojan:Win32/XWorm.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 57 33 d2 30 01 8b 45 ?? 03 c1 f7 75 ?? 0f b6 04 57 33 d2 30 41 01 8b 45 d0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}