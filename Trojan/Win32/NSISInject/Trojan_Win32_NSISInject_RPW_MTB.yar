
rule Trojan_Win32_NSISInject_RPW_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 ?? fd ff ff 50 ff 55 d8 89 45 ec 83 7d ec ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}