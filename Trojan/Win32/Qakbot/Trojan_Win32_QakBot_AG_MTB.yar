
rule Trojan_Win32_QakBot_AG_MTB{
	meta:
		description = "Trojan:Win32/QakBot.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 3b db 0f 84 90 01 04 c1 e0 00 8b 4d 90 01 01 eb 90 01 01 c7 44 01 90 01 05 81 44 01 40 43 46 01 00 eb 90 01 01 c7 44 01 90 01 05 81 44 01 40 14 ad 00 00 3a c9 0f 84 90 00 } //01 00 
		$a_03_1 = {3a f6 0f 84 90 01 04 c7 44 01 90 01 05 81 6c 01 90 01 05 66 3b ff 0f 84 90 0a 35 00 c7 44 01 90 01 05 81 44 01 40 9e 32 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}