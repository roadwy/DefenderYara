
rule Trojan_Win32_Redline_MQQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.MQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 59 8a 44 04 90 01 01 30 85 90 01 04 45 81 fd 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}