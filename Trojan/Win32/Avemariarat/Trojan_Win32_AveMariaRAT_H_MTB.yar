
rule Trojan_Win32_AveMariaRAT_H_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 0e 30 0a 42 83 e8 } //02 00 
		$a_01_1 = {33 c2 c1 c0 } //00 00 
	condition:
		any of ($a_*)
 
}