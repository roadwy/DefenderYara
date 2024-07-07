
rule Trojan_Win32_Trickbot_SV_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec 90 01 04 a1 90 01 04 33 c5 89 45 fc c7 85 90 01 02 ff ff 90 01 01 00 00 00 c6 85 90 01 02 ff ff 90 01 01 c6 85 90 01 02 ff ff 90 01 01 c6 85 90 01 02 ff ff 90 01 01 c6 85 90 01 02 ff ff 90 01 01 c6 85 90 01 02 ff ff 90 01 01 c6 85 90 01 02 ff ff 90 01 01 c6 85 90 01 02 ff ff 90 01 01 c6 85 90 01 02 ff ff 90 01 01 c6 85 90 01 02 ff ff 90 01 01 53 c6 85 90 01 02 ff ff 90 01 01 33 db c6 85 90 01 02 ff ff 90 01 01 8b d3 56 c6 85 90 01 02 ff ff 90 01 01 8a 85 90 01 02 ff ff 57 88 9d 90 01 02 ff ff 8a 84 15 90 01 02 ff ff 0f be 8d 90 01 02 ff ff 0f be c0 33 c1 88 84 15 90 01 02 ff ff 42 83 fa 0c 72 90 00 } //5
		$a_01_1 = {4d 61 69 6c 43 6c 69 65 6e 74 2e 64 6c 6c } //1 MailClient.dll
		$a_01_2 = {4d 6f 76 65 4c 65 66 74 } //1 MoveLeft
		$a_01_3 = {52 65 6c 65 61 73 65 } //1 Release
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}