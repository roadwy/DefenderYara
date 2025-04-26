
rule Worm_Win32_Vobfus_CJ{
	meta:
		description = "Worm:Win32/Vobfus.CJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 03 00 00 00 6a 00 6a 04 6a 01 6a 00 8d 45 b0 50 6a 10 68 80 08 00 00 ff 15 ?? ?? ?? ?? 83 c4 1c c7 45 a8 ?? ?? ?? ?? c7 45 a0 03 40 00 00 8d 55 a0 8b 4d b0 33 c0 2b 41 14 c1 e0 04 8b 4d b0 8b 49 0c 03 c8 ff 15 ?? ?? ?? ?? 8d 55 08 89 55 98 c7 45 90 (00 8d 55 90 90 8b 45 b0 b9 01 00 00 00 2b 48 14 c1 e1 04 8b 45 b0 8b 40 0c 03 c8 ff 15 ?? ?? ?? ?? 8d 4d 0c 89 4d 88 c7 45 80 03 40 00 00 8d 55 80 8b 45 b0 b9 02 00 00 00 2b 48 14 c1 e1 04 |)} //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}