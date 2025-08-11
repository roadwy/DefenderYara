
rule Trojan_Win32_Lazy_GW_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c2 80 c1 ?? 32 4c 45 ?? 8d 42 ?? 88 0c 3e 46 0f b7 d0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}