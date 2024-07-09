
rule Trojan_Win32_Viknok_C{
	meta:
		description = "Trojan:Win32/Viknok.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {70 3d 25 75 26 74 3d 25 75 26 65 3d 25 75 } //1 p=%u&t=%u&e=%u
		$a_03_1 = {8b 42 3c 03 c2 8b 78 78 89 45 ?? 85 ff 74 ?? 83 65 ?? 00 03 fa 8b 4f 20 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}