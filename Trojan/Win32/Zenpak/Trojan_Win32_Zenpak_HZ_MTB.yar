
rule Trojan_Win32_Zenpak_HZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.HZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 3b 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8a 4c 24 ?? 88 0c 3b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}