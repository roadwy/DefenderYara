
rule Trojan_Win32_Zbot_RPF_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 55 db 8b 45 e8 8b 55 08 0f b6 4d e3 01 f1 88 0c 02 8b 45 ec 0f b6 4d db 31 f1 88 0c 02 ff 45 f0 81 7d f0 ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}