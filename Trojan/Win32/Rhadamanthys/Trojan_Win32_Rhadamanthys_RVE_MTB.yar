
rule Trojan_Win32_Rhadamanthys_RVE_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.RVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 06 83 7f 14 0f 8d 0c 10 8b c7 76 02 8b 07 8a 09 80 f1 2a 88 0c 10 42 3b 56 10 72 db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}