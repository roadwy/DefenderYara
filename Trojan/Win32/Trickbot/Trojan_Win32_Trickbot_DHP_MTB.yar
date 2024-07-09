
rule Trojan_Win32_Trickbot_DHP_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8a 84 35 ?? ?? ?? ?? 81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 83 c4 0c 8a 94 15 90 1b 00 32 c2 88 03 } //1
		$a_81_1 = {4d 43 64 4d 31 41 77 7c 32 53 61 47 32 72 64 47 7a 79 49 33 55 37 24 4b 25 76 65 74 75 69 56 } //1 MCdM1Aw|2SaG2rdGzyI3U7$K%vetuiV
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}