
rule Trojan_Win32_RedLine_MT_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 33 d2 f7 75 14 8b c2 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 55 08 0f be 04 02 c1 e0 ?? 6b c0 ?? 99 b9 57 00 00 00 f7 f9 6b c0 36 99 83 e2 ?? 03 c2 c1 f8 ?? 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}