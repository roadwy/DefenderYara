
rule Trojan_Win32_DanaBot_CCJN_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 80 b8 ?? ?? ?? ?? 09 75 0a 8b 45 fc c6 80 ?? ?? ?? ?? 0f ff 45 fc 83 7d fc 20 75 e1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}