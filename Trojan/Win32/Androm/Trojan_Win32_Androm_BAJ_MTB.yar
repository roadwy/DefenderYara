
rule Trojan_Win32_Androm_BAJ_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c3 03 c7 89 45 ?? c7 45 a4 39 19 00 00 6a 00 e8 [0-1f] 8b 55 ?? 03 55 ?? 81 ea 39 19 00 00 2b d7 03 c2 31 06 83 c3 04 83 c6 04 3b 5d ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}