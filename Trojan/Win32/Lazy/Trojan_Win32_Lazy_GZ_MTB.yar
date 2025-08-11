
rule Trojan_Win32_Lazy_GZ_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 30 0f b7 d1 80 c3 ?? 32 5c 55 ?? 40 88 5c 30 ?? 41 3b c7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}