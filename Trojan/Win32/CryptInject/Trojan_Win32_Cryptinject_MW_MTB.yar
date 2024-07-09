
rule Trojan_Win32_Cryptinject_MW_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 49 00 e8 ?? ?? ?? ?? 8b 4c 24 ?? 30 04 0e b8 01 00 00 00 29 44 24 ?? 83 7c 24 04 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}