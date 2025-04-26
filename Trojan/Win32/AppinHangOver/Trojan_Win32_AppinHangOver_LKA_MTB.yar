
rule Trojan_Win32_AppinHangOver_LKA_MTB{
	meta:
		description = "Trojan:Win32/AppinHangOver.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 00 10 40 00 36 80 31 0e 41 81 f9 7d 06 44 00 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}