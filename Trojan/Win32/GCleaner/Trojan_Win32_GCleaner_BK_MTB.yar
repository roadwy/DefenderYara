
rule Trojan_Win32_GCleaner_BK_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 14 50 e8 ?? 3b 04 00 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}