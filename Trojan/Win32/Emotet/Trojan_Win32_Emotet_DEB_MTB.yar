
rule Trojan_Win32_Emotet_DEB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 ?? 8a 54 14 ?? 32 da 88 5d 00 45 48 89 44 24 ?? 75 } //1
		$a_02_1 = {0f b6 06 0f b6 cb 03 c1 8b cf 99 f7 f9 8b 45 14 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d 0c 89 45 14 75 } //1
		$a_81_2 = {6e 44 39 6e 52 33 52 4c 68 49 6e 6a 56 63 37 54 56 64 54 59 55 39 38 71 6f 58 65 37 50 70 73 } //1 nD9nR3RLhInjVc7TVdTYU98qoXe7Pps
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}