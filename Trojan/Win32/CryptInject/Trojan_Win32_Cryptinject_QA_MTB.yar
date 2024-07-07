
rule Trojan_Win32_Cryptinject_QA_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.QA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 55 fc 0f b6 45 ff 33 c2 88 45 ff 68 90 01 04 e8 90 01 04 83 c4 04 8a 4d fc 80 c1 01 88 4d fc 68 90 01 04 e8 90 01 04 83 c4 04 8b 55 f0 8a 45 ff 88 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}