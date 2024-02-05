
rule Trojan_Win32_Gatak_DEA_MTB{
	meta:
		description = "Trojan:Win32/Gatak.DEA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 d8 8b 4d dc 0f b6 04 01 8b 4d d8 83 e1 03 83 c1 02 0f b6 4c 0d f1 29 c8 88 c2 8b 45 e8 03 45 ec 8b 4d d8 88 14 08 } //00 00 
	condition:
		any of ($a_*)
 
}