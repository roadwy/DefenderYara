
rule Trojan_Win32_SquirrelWaffle_DB{
	meta:
		description = "Trojan:Win32/SquirrelWaffle.DB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ea 02 0f b6 c8 8a c3 2b ce 83 e9 2e 2a c1 89 0d ?? ?? ?? ?? 04 08 a2 ?? ?? ?? ?? 83 fa 02 90 09 07 00 29 34 95 } //1
		$a_03_1 = {0f b6 cb 66 8b c1 66 03 c0 66 03 c8 8b 44 24 ?? 05 98 89 0b 01 66 2b ce 83 6c 24 ?? 01 89 07 8b 7c 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}