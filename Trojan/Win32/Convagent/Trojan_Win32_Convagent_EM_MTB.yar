
rule Trojan_Win32_Convagent_EM_MTB{
	meta:
		description = "Trojan:Win32/Convagent.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 45 ec 88 02 c7 85 a8 fa ff ff 02 00 00 00 8b 45 ec 33 d2 b9 58 02 00 00 f7 f1 8b 85 38 fd ff ff 03 45 ec 8a 8c 15 64 fd ff ff 88 08 } //00 00 
	condition:
		any of ($a_*)
 
}