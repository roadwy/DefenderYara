
rule Trojan_Win32_Redline_GEC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 29 d0 89 c2 8b 45 ?? 01 d0 0f b6 00 83 e0 ?? 31 d8 88 45 ?? 0f b6 45 ?? 8d 0c 00 8b 55 ?? 8b 45 ?? 01 d0 89 ca 88 10 8b 55 ?? 8b 45 ?? 01 d0 0f b6 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}