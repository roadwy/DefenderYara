
rule Trojan_Win32_Midie_SIBG3_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBG3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 00 00 00 00 8a 81 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 74 ?? [0-20] 34 ?? 2c ?? [0-20] 34 ?? [0-20] 04 ?? [0-20] 88 81 90 1b 00 83 c1 01 90 18 8a 81 90 1b 00 81 f9 90 1b 01 90 18 b0 00 b9 00 00 00 00 8d 45 ?? 50 6a 40 68 90 1b 01 68 90 1b 00 ff 15 ?? ?? ?? ?? b9 90 1b 00 ff d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}