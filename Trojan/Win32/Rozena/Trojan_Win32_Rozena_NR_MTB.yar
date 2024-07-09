
rule Trojan_Win32_Rozena_NR_MTB{
	meta:
		description = "Trojan:Win32/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 85 53 fe ff ff 89 04 24 e8 5a 5c 00 00 8d 95 4c fe ff ff } //3
		$a_03_1 = {89 54 24 0c c7 44 24 08 ?? ?? ?? ?? 89 44 24 04 8d 85 53 fe ff ff 89 04 24 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}