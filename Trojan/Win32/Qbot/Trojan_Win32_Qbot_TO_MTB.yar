
rule Trojan_Win32_Qbot_TO_MTB{
	meta:
		description = "Trojan:Win32/Qbot.TO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01 8b e5 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}