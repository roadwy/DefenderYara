
rule Trojan_Win32_Alureon_ET{
	meta:
		description = "Trojan:Win32/Alureon.ET,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 0d 2f 00 00 74 23 3d 0c 2f 00 00 74 1c 3d 05 2f 00 00 74 15 3d 06 2f 00 00 74 0e 3d 07 2f 00 00 74 07 3d 14 2f 00 00 75 } //1
		$a_03_1 = {8d 45 f8 50 8d 45 fc 50 68 05 00 00 20 ff 77 08 c7 45 f8 04 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 0d 39 75 fc 75 08 33 c0 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}