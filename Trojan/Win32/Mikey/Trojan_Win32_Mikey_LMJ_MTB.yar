
rule Trojan_Win32_Mikey_LMJ_MTB{
	meta:
		description = "Trojan:Win32/Mikey.LMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 85 b8 fc ff ff 99 2b c2 d1 f8 33 c9 85 c0 7e ?? 66 83 b4 4d bc fe ff ff 7c 41 3b c8 } //20
		$a_01_1 = {8b 46 0c 31 03 8b 06 83 e8 15 41 c1 e8 02 83 c3 04 3b c8 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}