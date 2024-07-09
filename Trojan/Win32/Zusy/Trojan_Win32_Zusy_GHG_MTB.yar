
rule Trojan_Win32_Zusy_GHG_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 d8 85 40 00 5a b9 ?? ?? ?? ?? 09 c0 e8 ?? ?? ?? ?? 89 c1 31 16 81 c6 ?? ?? ?? ?? 01 c1 49 39 fe 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}