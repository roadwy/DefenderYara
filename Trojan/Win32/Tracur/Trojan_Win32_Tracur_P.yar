
rule Trojan_Win32_Tracur_P{
	meta:
		description = "Trojan:Win32/Tracur.P,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff b0 9c 00 00 00 [0-a0] 8f 45 dc [0-1a] 81 75 dc 78 42 76 39 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}