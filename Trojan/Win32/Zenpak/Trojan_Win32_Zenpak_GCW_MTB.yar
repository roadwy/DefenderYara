
rule Trojan_Win32_Zenpak_GCW_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 30 83 c2 ?? 83 f2 ?? 8d 05 ?? ?? ?? ?? 89 28 31 c2 b8 ?? ?? ?? ?? 89 d8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 01 38 8d 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}