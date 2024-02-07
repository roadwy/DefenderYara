
rule Backdoor_Win32_Sapphire_SB_MSR{
	meta:
		description = "Backdoor:Win32/Sapphire.SB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 65 00 72 00 6e 00 66 00 32 00 31 00 5f 00 64 00 79 00 6d 00 6a 00 63 00 6e 00 2e 00 6b 00 6a 00 63 00 } //01 00  wernf21_dymjcn.kjc
		$a_01_1 = {25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 2e 00 2e 00 5c 00 } //01 00  %TEMP%\..\
		$a_01_2 = {4c 6e 6b 44 6c 6c 2e 64 6c 6c } //01 00  LnkDll.dll
		$a_01_3 = {2e 00 75 00 77 00 74 00 } //01 00  .uwt
		$a_01_4 = {4e 00 76 00 69 00 65 00 77 00 33 00 32 00 20 00 41 00 70 00 69 00 53 00 65 00 74 00 20 00 4c 00 69 00 62 00 } //00 00  Nview32 ApiSet Lib
	condition:
		any of ($a_*)
 
}