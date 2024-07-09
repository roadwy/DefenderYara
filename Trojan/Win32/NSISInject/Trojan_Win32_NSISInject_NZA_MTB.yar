
rule Trojan_Win32_NSISInject_NZA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 81 [0-05] 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc } //1
		$a_03_1 = {6a 01 68 00 00 00 80 b9 04 00 00 00 c1 e1 00 8b 55 0c 8b 04 0a 50 ff 15 [0-04] 89 45 ec 6a 00 8b 4d ec 51 ff 15 [0-04] 89 45 f0 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}