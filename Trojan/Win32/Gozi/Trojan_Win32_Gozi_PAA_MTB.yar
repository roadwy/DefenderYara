
rule Trojan_Win32_Gozi_PAA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 75 c8 01 f1 81 e1 90 02 04 8b 75 ec 8b 5d d0 8a 1c 1e 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 d0 88 1c 31 8b 4d f0 39 cf 8b 4d c4 89 55 d8 89 4d dc 89 7d d4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}