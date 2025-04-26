
rule Trojan_Win32_Qbot_DEA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ba 82 00 01 00 ba 82 00 01 00 ba 82 00 01 00 ba 82 00 01 00 ba 82 00 01 00 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d 90 1b 00 8b ff a1 ?? ?? ?? ?? 8b 0d 90 1b 00 89 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}