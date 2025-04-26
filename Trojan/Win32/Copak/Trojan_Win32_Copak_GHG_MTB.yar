
rule Trojan_Win32_Copak_GHG_MTB{
	meta:
		description = "Trojan:Win32/Copak.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 ea 31 3b 81 c0 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 40 39 cb 75 e8 c3 c3 81 e9 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 39 ff 74 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}