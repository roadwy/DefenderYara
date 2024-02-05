
rule Trojan_Win32_Ekstak_CF_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {d8 f1 dd 1d 90 01 04 8d 35 90 01 04 8d 3d 90 01 04 a5 81 7d 90 01 01 4e e6 40 bb 74 90 01 01 8b 0d 90 01 04 81 e1 00 00 ff ff 85 c9 75 90 01 01 c7 45 90 01 01 4f e6 40 bb 90 00 } //01 00 
		$a_02_1 = {6a 0a 58 50 ff 75 9c 56 56 ff 15 90 01 04 50 e8 90 01 04 89 45 a0 50 e8 90 01 04 8b 45 ec 8b 08 8b 09 89 4d 98 50 51 e8 90 01 04 59 59 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}