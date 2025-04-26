
rule Trojan_Win32_Fugrafa_RPY_MTB{
	meta:
		description = "Trojan:Win32/Fugrafa.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 f9 6a 00 89 85 ac fd ff ff 8b c3 99 f7 fe 0f af 8d ac fd ff ff 89 85 b0 fd ff ff 0f af b5 b0 fd ff ff 2b f9 8b c7 99 2b de 2b c2 d1 f8 89 85 a0 fd ff ff 8b c3 99 2b c2 d1 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}