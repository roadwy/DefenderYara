
rule Trojan_Win32_DllHijack_BZ_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f0 8b d7 50 8d 4d ec e8 ?? ?? ?? ?? 8b 45 e4 83 c7 06 30 45 f0 83 c4 04 30 65 f1 0f b6 45 ea 30 45 f2 0f b6 45 eb 30 45 f3 8b c6 8b 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}