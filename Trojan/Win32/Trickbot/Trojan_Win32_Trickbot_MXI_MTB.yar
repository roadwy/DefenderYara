
rule Trojan_Win32_Trickbot_MXI_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 00 01 00 00 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d 0c 89 45 14 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}