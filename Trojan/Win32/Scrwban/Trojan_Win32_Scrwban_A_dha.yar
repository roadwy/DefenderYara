
rule Trojan_Win32_Scrwban_A_dha{
	meta:
		description = "Trojan:Win32/Scrwban.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_81_0 = {64 6f 77 6e 6c 6f 61 64 3f 63 69 64 3d 34 42 46 41 32 38 36 38 36 36 42 31 43 30 32 41 26 72 65 73 69 64 3d 34 42 46 41 32 38 36 38 36 36 42 31 43 30 32 41 25 32 31 31 30 35 26 61 75 74 68 6b 65 79 3d 41 4c 73 33 4a 47 61 58 69 61 37 6f 75 6c 34 } //00 00  download?cid=4BFA286866B1C02A&resid=4BFA286866B1C02A%21105&authkey=ALs3JGaXia7oul4
	condition:
		any of ($a_*)
 
}