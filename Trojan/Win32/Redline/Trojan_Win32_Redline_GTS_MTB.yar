
rule Trojan_Win32_Redline_GTS_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 ca 80 f2 ?? d0 c2 0f b6 ca 01 c1 31 c1 b2 46 28 ca 80 f2 ?? 0f b6 ca 01 c1 31 c1 80 c1 ?? 30 c1 80 c1 ?? c0 c1 ?? 88 4c 05 d0 83 f8 0e 74 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}