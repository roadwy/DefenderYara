
rule Trojan_Win32_PonyLoader_DEA_MTB{
	meta:
		description = "Trojan:Win32/PonyLoader.DEA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 f0 8b 55 08 03 32 8b 45 08 89 30 8b 4d 08 8b 11 81 ea 36 a6 06 00 8b 45 08 89 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}