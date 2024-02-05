
rule Trojan_Win32_Qakbot_FS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 6a 00 e8 } //00 00 
	condition:
		any of ($a_*)
 
}