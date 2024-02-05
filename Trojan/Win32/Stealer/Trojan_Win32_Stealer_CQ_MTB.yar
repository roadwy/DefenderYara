
rule Trojan_Win32_Stealer_CQ_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 f7 0f b6 04 17 8b 55 ec 30 04 0a 41 8b 45 f0 39 c8 75 dc } //02 00 
		$a_03_1 = {89 ca c1 ea 1e 31 ca 69 ca 90 02 04 8d 8c 08 90 02 04 89 0c 85 90 02 04 40 75 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}