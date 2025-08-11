
rule Trojan_Win32_Rhadamanthys_AC_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 81 70 6a 44 00 33 44 0c 18 83 c1 04 33 44 0c 1c 33 44 0c 18 8b d0 8b d8 c1 ea 18 c1 eb 10 0f b6 d2 0f b6 92 60 69 44 00 88 5c 24 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}