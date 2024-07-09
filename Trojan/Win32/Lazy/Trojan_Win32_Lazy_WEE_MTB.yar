
rule Trojan_Win32_Lazy_WEE_MTB{
	meta:
		description = "Trojan:Win32/Lazy.WEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 0b 8d 4d ?? e8 ?? ?? ?? ?? 8b 55 ?? 43 3b 9d ?? ?? ?? ?? 89 5d ?? 8b 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}