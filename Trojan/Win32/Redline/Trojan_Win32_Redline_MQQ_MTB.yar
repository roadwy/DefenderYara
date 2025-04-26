
rule Trojan_Win32_Redline_MQQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.MQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 59 8a 44 04 ?? 30 85 ?? ?? ?? ?? 45 81 fd ?? ?? ?? ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}