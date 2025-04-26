
rule Trojan_Win32_Kanots_A{
	meta:
		description = "Trojan:Win32/Kanots.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {3b c6 74 3e 83 f8 ff 74 39 ff b5 b0 fd ff ff 8d 8d b8 fd ff ff ff b5 b4 fd ff ff 51 50 } //1
		$a_01_1 = {c7 45 ec 65 78 70 6c c7 45 f0 6f 72 65 72 c7 45 f4 2e 65 78 65 c6 45 f8 00 } //1
		$a_03_2 = {56 57 be 8e 02 01 00 56 68 ?? ?? ?? ?? 53 } //1
		$a_01_3 = {ff b5 b4 fd ff ff 51 50 e8 a9 fc ff ff 83 c4 10 85 c0 74 19 68 00 80 00 00 56 ff b5 b4 fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}