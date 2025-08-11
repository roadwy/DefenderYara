
rule Trojan_Win32_Redline_AC_MTB{
	meta:
		description = "Trojan:Win32/Redline.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 29 4a 5b cd 35 d5 84 17 f3 ?? 4c d1 44 ec a7 37 59 8a 68 a5 86 f0 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}