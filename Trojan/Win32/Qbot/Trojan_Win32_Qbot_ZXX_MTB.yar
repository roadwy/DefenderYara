
rule Trojan_Win32_Qbot_ZXX_MTB{
	meta:
		description = "Trojan:Win32/Qbot.ZXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 35 35 35 } //1 X555
	condition:
		((#a_01_0  & 1)*1) >=1
 
}