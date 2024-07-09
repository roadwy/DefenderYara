
rule Trojan_Win32_Redline_GDB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 10 6b c0 ?? be ?? ?? ?? ?? 99 f7 fe 89 c2 8b 45 ?? 6b d2 ?? 31 d1 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f b6 14 08 29 f2 88 14 08 8b 45 ?? 83 c0 ?? 89 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}