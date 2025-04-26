
rule Trojan_Win32_Farfli_MAW_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f2 6a f8 9f 6a dd 0b 83 ?? ?? ?? ?? 64 24 01 89 44 24 02 0f 95 c4 66 8b c2 eb ?? f6 da 0f 31 } //1
		$a_01_1 = {67 fc 92 f5 04 ad 49 66 8b c2 f6 dc 3a e5 66 0f bb d8 52 66 0f a3 e0 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}