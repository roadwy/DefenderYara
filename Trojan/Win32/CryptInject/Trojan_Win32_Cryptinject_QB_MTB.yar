
rule Trojan_Win32_Cryptinject_QB_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.QB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 0f b6 08 8b 45 f0 99 f7 7d ec 89 d0 89 c2 8b 45 08 01 d0 0f b6 00 31 c1 89 ca 8b 45 f4 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}