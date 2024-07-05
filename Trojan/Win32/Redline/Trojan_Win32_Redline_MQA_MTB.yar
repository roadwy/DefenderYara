
rule Trojan_Win32_Redline_MQA_MTB{
	meta:
		description = "Trojan:Win32/Redline.MQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 84 05 c0 00 00 00 30 04 39 47 89 7d 90 01 01 3b bd 90 01 04 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}