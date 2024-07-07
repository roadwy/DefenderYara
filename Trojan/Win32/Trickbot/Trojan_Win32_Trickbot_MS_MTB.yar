
rule Trojan_Win32_Trickbot_MS_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 08 89 45 90 01 01 68 00 04 00 00 8d 85 90 01 04 50 6a 00 ff 90 01 02 c7 45 b4 90 01 04 6a 01 8b 4d 90 01 01 51 8d 95 90 01 04 52 ff 90 01 02 85 c0 90 00 } //1
		$a_80_1 = {4d 4f 66 48 3f 36 4d 34 32 46 32 35 32 6c 6f 4c 74 30 4e 7e 37 3f 43 4f 73 53 77 79 69 74 68 38 48 59 6e 6e 50 } //MOfH?6M42F252loLt0N~7?COsSwyith8HYnnP  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}