
rule Trojan_Win32_Convagent_KKA_MTB{
	meta:
		description = "Trojan:Win32/Convagent.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 01 d0 0f b6 00 0f be c0 0f b6 d0 8b 45 e4 89 94 85 24 ff ff ff 83 45 e4 01 } //20
		$a_01_1 = {83 c0 02 8b 84 85 d0 fe ff ff 31 c2 8b 45 e8 83 c0 03 8b 84 85 d0 fe ff ff 31 c2 b8 1f 00 00 00 2b 45 e8 8b 84 85 60 ff ff ff 31 c2 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}