
rule Trojan_Win32_Razy_GN_MTB{
	meta:
		description = "Trojan:Win32/Razy.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 39 29 d2 68 c3 b6 f8 44 8b 14 24 83 c4 ?? 81 c1 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 39 f1 75 cf } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}