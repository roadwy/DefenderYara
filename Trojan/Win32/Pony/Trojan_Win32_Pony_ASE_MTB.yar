
rule Trojan_Win32_Pony_ASE_MTB{
	meta:
		description = "Trojan:Win32/Pony.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ad 30 ca b9 ad 30 ca b9 1d 76 fd 0b 68 8a 37 7e } //1
		$a_01_1 = {0a f1 82 1d 76 fd 0b 6f 88 30 ca 1f 44 fd 01 57 4f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}