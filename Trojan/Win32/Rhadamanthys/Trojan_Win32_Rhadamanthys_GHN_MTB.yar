
rule Trojan_Win32_Rhadamanthys_GHN_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c3 8d 4c 24 28 03 f0 8a 16 02 f2 0f b6 c6 03 c8 0f b6 01 88 06 88 11 0f b6 0e 0f b6 c2 03 c8 0f b6 c1 8b 4c 24 ?? 0f b6 44 04 ?? 30 04 0f 47 3b 7c 24 14 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}