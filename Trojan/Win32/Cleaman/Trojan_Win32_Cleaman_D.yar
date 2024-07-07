
rule Trojan_Win32_Cleaman_D{
	meta:
		description = "Trojan:Win32/Cleaman.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b ca c1 e1 07 d1 ea 0b ca 88 88 90 01 04 40 90 00 } //5
		$a_01_1 = {75 04 c6 45 00 e9 6a 04 8d 45 01 50 2b f5 83 c6 fb } //1
		$a_01_2 = {8b f7 f7 de 80 3c 16 5c 0f 84 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}