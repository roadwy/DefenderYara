
rule Trojan_Win32_AveMariaRAT_B_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 01 f7 d0 85 c0 74 90 01 01 88 04 1a 83 e9 90 01 01 42 81 f9 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}