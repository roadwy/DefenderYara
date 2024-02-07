
rule Trojan_Win32_Qbot_A{
	meta:
		description = "Trojan:Win32/Qbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 36 35 5a 58 4f 4b 35 4b 63 7c 5a 35 64 5f 7c 74 4b 46 66 4f 72 7a 37 4b 74 75 65 44 2e 70 64 62 } //01 00  265ZXOK5Kc|Z5d_|tKFfOrz7KtueD.pdb
		$a_00_1 = {70 00 72 00 65 00 76 00 69 00 65 00 77 00 73 00 34 00 31 00 67 00 65 00 6f 00 72 00 67 00 65 00 4b 00 74 00 63 00 } //01 00  previews41georgeKtc
		$a_00_2 = {53 00 69 00 6e 00 63 00 65 00 66 00 4c 00 62 00 65 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 74 00 68 00 65 00 61 00 70 00 70 00 6f 00 69 00 6e 00 74 00 6d 00 65 00 6e 00 74 00 } //00 00  SincefLbeGoogletheappointment
	condition:
		any of ($a_*)
 
}