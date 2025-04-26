
rule Trojan_Win32_Ranumbot_RHJ_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 33 db 33 ff 3b eb 7e ?? 56 8b 44 24 ?? 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 fd 19 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}