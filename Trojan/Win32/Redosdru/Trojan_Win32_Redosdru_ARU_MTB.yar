
rule Trojan_Win32_Redosdru_ARU_MTB{
	meta:
		description = "Trojan:Win32/Redosdru.ARU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f8 83 c2 01 89 55 f8 8b 45 f8 3b 45 f4 7d 30 8b 4d fc 03 4d f8 0f be 11 0f be 45 f0 2b d0 8b 4d fc 03 4d f8 88 11 8b 55 fc 03 55 f8 0f be 02 0f be 4d ec 33 c1 8b 55 fc 03 55 f8 88 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}