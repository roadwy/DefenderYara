
rule Trojan_Win32_LightHand_A_dha{
	meta:
		description = "Trojan:Win32/LightHand.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {0f 00 00 00 c0 ea 07 0f 1f 00 0f 90 01 04 d0 c1 88 90 01 03 48 ff c8 48 85 c0 7f 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}