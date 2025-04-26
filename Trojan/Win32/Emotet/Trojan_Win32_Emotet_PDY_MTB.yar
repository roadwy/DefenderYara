
rule Trojan_Win32_Emotet_PDY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 ?? 83 c5 01 c7 84 24 ?? ?? ?? ?? ff ff ff ff 0f b6 94 14 ?? ?? ?? ?? 30 55 } //1
		$a_81_1 = {62 69 66 48 6b 42 69 57 67 5a 51 5a 51 42 68 44 52 74 76 34 68 4b 6e 30 49 48 66 72 30 50 6d 7a 4d 43 30 } //1 bifHkBiWgZQZQBhDRtv4hKn0IHfr0PmzMC0
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}