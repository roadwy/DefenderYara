
rule Trojan_Win32_Etchfro_D{
	meta:
		description = "Trojan:Win32/Etchfro.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 30 50 8d 7c 30 18 51 6a 00 } //1
		$a_01_1 = {c6 06 4d c6 46 01 5a 76 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}