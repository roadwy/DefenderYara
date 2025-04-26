
rule Trojan_Win32_IcedId_DHA_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 40 83 c4 2c 89 85 90 1b 01 0f b6 94 15 ?? ?? ?? ?? 30 50 ff } //1
		$a_81_1 = {52 50 35 64 52 46 42 37 41 71 63 42 63 77 77 71 76 70 62 46 6a 6c 46 70 74 71 64 4a 71 34 43 } //1 RP5dRFB7AqcBcwwqvpbFjlFptqdJq4C
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}