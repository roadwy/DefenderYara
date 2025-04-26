
rule Trojan_Win32_Qbot_KDU_MTB{
	meta:
		description = "Trojan:Win32/Qbot.KDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a c3 2a c2 83 c1 09 83 ee 02 8d 50 2f 0f b6 c2 2b c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}