
rule Trojan_Win32_Phoenix_RPY_MTB{
	meta:
		description = "Trojan:Win32/Phoenix.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 ff 76 50 33 c0 50 ff 95 74 ff ff ff 8b f8 85 ff 0f 84 58 02 00 00 6a 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 75 e4 ff 55 dc 89 45 fc 85 c0 75 41 85 db 75 18 ff 76 34 ff 75 e4 ff 55 b8 6a 40 68 00 30 00 00 ff 76 50 ff 76 34 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}