
rule Trojan_Win32_Etchfro_B{
	meta:
		description = "Trojan:Win32/Etchfro.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 02 c6 01 4d 5e c6 41 01 5a 39 } //1
		$a_01_1 = {ff 74 18 50 8d 7c 18 18 6a 00 } //1
		$a_01_2 = {f6 ea 30 1c 37 02 c1 47 8a d8 3b 7d 0c 72 ed } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}