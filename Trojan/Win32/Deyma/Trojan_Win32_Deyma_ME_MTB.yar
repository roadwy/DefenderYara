
rule Trojan_Win32_Deyma_ME_MTB{
	meta:
		description = "Trojan:Win32/Deyma.ME!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 8b 11 8b 45 f8 8b 48 08 8a 14 11 88 55 ff } //5
		$a_01_1 = {55 8b ec 83 ec 08 89 4d fc 8b 45 fc 89 45 f8 6b 45 08 18 8b 4d f8 03 01 8b e5 5d c2 04 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}