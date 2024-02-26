
rule Trojan_Win32_AsyncRAT_G_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {ff 8b f0 ff 75 } //02 00 
		$a_01_1 = {ff 8a 1e 32 18 ff 75 } //02 00 
		$a_01_2 = {ff 88 18 8b 45 d0 83 c0 } //00 00 
	condition:
		any of ($a_*)
 
}