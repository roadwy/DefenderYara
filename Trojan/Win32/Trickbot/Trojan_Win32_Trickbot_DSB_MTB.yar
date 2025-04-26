
rule Trojan_Win32_Trickbot_DSB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 33 d2 b9 03 00 00 00 f7 f1 8b 45 f0 0f be 0c 10 8b 55 fc 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d fc 88 81 ?? ?? ?? ?? eb } //1
		$a_00_1 = {31 34 42 45 46 41 57 4b 55 31 58 43 51 4d 49 59 4d 4f 46 } //1 14BEFAWKU1XCQMIYMOF
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}