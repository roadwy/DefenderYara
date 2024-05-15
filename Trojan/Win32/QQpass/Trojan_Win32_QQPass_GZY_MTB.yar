
rule Trojan_Win32_QQPass_GZY_MTB{
	meta:
		description = "Trojan:Win32/QQPass.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {5d 81 ed 10 00 00 00 81 ed 90 01 04 e9 90 01 04 03 df d1 6b b8 28 f6 a3 90 01 04 c0 4c 00 00 00 b9 a1 05 00 00 ba 90 01 04 30 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}