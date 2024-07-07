
rule Trojan_Win32_Redline_MQW_MTB{
	meta:
		description = "Trojan:Win32/Redline.MQW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 3c 44 03 c6 0f b6 c0 59 8a 44 04 40 30 85 90 01 04 45 81 fd 90 01 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}