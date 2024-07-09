
rule Trojan_Win32_UrSniff_RPX_MTB{
	meta:
		description = "Trojan:Win32/UrSniff.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 02 8b d6 2b 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 03 d1 8d 81 37 ff ff ff 3d b9 0e 00 00 8b fb } //1
		$a_01_1 = {8b 4c 24 10 05 0c d7 85 01 89 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}