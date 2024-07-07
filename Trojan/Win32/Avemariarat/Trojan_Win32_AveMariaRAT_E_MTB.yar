
rule Trojan_Win32_AveMariaRAT_E_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0f c0 c8 90 01 01 32 82 90 01 04 41 88 44 0f ff 8d 42 90 01 01 99 f7 fe 3b cb 72 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}