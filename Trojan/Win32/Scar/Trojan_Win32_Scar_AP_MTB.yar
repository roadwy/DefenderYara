
rule Trojan_Win32_Scar_AP_MTB{
	meta:
		description = "Trojan:Win32/Scar.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {19 4c ff 08 4c ff 0d ac 00 07 00 32 06 00 70 ff 68 ff 64 ff 29 06 00 74 ff 6c ff 4c ff 00 02 00 0d 04 50 ff 0a 08 00 04 00 35 50 ff 00 07 } //1
		$a_01_1 = {2a 23 28 ff 1b 29 00 2a 23 24 ff 1b 26 00 2a 46 14 ff 0a 2a 00 08 00 74 0c ff 32 1c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}