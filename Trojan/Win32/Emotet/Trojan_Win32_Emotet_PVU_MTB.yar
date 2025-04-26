
rule Trojan_Win32_Emotet_PVU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVU!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 0a 8b 4c 24 18 32 1c 31 c6 44 24 47 1e 8b 74 24 3c 8a 7c 24 47 8b 4c 24 14 88 1c 31 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}