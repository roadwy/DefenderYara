
rule Trojan_Win32_Ramdo_A{
	meta:
		description = "Trojan:Win32/Ramdo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 89 45 90 01 01 8b 45 90 01 01 8b 90 03 01 01 40 48 0c 89 90 03 01 01 45 4d 90 01 01 8b 90 03 01 01 45 55 90 01 01 83 90 03 01 01 c0 c2 0c 90 00 } //1
		$a_03_1 = {6a 03 6a 00 e8 90 01 04 83 c4 0c 89 45 fc 8b 45 10 50 8b 4d 0c 51 8b 55 08 52 ff 55 fc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}