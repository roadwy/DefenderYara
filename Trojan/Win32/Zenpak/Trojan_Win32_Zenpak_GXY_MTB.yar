
rule Trojan_Win32_Zenpak_GXY_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 6a 08 99 5e f7 fe 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 81 f9 0c ac 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}