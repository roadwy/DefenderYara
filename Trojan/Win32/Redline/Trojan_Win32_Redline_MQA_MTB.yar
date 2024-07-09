
rule Trojan_Win32_Redline_MQA_MTB{
	meta:
		description = "Trojan:Win32/Redline.MQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 84 05 c0 00 00 00 30 04 39 47 89 7d ?? 3b bd ?? ?? ?? ?? 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}