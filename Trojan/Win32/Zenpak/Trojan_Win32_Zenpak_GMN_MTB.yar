
rule Trojan_Win32_Zenpak_GMN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 f2 88 d0 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 83 c4 ?? 5e 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}