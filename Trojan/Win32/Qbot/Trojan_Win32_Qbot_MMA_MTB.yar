
rule Trojan_Win32_Qbot_MMA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b 0d 90 01 04 83 c1 01 a1 90 01 04 a3 90 01 04 a1 90 01 04 31 0d 90 01 04 8b ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}