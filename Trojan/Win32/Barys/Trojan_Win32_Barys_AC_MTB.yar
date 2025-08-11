
rule Trojan_Win32_Barys_AC_MTB{
	meta:
		description = "Trojan:Win32/Barys.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 89 08 50 45 43 6f 6d 70 61 63 74 32 00 ee 05 9e 8b c4 b7 67 3c 87 2f 7c e1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}