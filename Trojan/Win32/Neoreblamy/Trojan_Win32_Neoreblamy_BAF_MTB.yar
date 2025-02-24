
rule Trojan_Win32_Neoreblamy_BAF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 14 78 8d 87 ?? ?? 00 00 0f b7 c8 8b c1 23 c2 03 c0 2b c8 03 ca 0f b7 f1 8d 04 17 33 d2 6a 19 59 f7 f1 8b ca d3 e6 01 75 ec 47 39 7b 10 77 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}