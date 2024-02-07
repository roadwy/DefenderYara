
rule Trojan_Win32_Farfli_MZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 59 72 65 65 6e 51 69 6c 6c 6d } //01 00  cYreenQillm
		$a_01_1 = {2e 74 68 65 6d 69 64 61 } //01 00  .themida
		$a_01_2 = {2e 62 6f 6f 74 } //01 00  .boot
		$a_01_3 = {54 65 6c 65 67 72 61 6d 44 6c 6c 2e 64 6c 6c } //01 00  TelegramDll.dll
		$a_01_4 = {2f 64 75 6d 70 73 74 61 74 75 73 } //01 00  /dumpstatus
		$a_01_5 = {2f 63 68 65 63 6b 70 72 6f 74 65 63 74 69 6f 6e } //01 00  /checkprotection
		$a_01_6 = {2f 66 6f 72 63 65 72 75 6e } //00 00  /forcerun
	condition:
		any of ($a_*)
 
}