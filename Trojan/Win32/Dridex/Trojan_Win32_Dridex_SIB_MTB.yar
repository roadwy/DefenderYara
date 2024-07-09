
rule Trojan_Win32_Dridex_SIB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 [0-4a] 8a 04 0a [0-05] 8a 64 24 27 28 e0 [0-0a] 89 4c 24 10 [0-05] 89 74 24 08 88 44 24 07 [0-1a] 8b 44 24 08 8b 54 24 10 8a 5c 24 07 88 1c 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}