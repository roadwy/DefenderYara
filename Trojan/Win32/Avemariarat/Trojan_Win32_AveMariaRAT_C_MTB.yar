
rule Trojan_Win32_AveMariaRAT_C_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0e c0 c8 90 01 01 32 82 90 01 04 c7 45 90 01 05 88 04 0e 8d 42 90 01 01 99 f7 7d 90 01 01 41 81 f9 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}