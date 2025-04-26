
rule Trojan_Win32_Trickbot_DHL_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f b6 84 35 b8 e5 ff ff 0f b6 c9 03 c1 99 b9 42 1a 00 00 f7 f9 0f b6 94 15 b8 e5 ff ff 30 53 ff 83 7d 0c 00 75 9b } //1
		$a_81_1 = {4f 77 63 52 4a 45 43 32 67 35 4e 4a 39 77 62 4f 6d 4a 6e 55 4f 35 6e 4b 31 4c 57 58 70 62 62 6e 64 78 6c 4e 34 } //1 OwcRJEC2g5NJ9wbOmJnUO5nK1LWXpbbndxlN4
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}