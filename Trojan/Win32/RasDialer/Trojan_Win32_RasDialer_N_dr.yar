
rule Trojan_Win32_RasDialer_N_dr{
	meta:
		description = "Trojan:Win32/RasDialer.N!dr,SIGNATURE_TYPE_PEHSTR_EXT,35 00 33 00 09 00 00 0a 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 65 70 6c 90 01 01 2e 65 78 65 90 00 } //0a 00 
		$a_00_1 = {6d 6b 63 32 34 38 39 2e 65 78 65 } //0a 00  mkc2489.exe
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 56 69 73 69 6f 20 52 41 53 20 53 63 72 69 70 74 } //0a 00  Software\Visio RAS Script
		$a_00_3 = {4b 00 77 00 5a 00 5f 00 33 00 } //05 00  KwZ_3
		$a_00_4 = {65 70 6c 25 64 2e 65 78 65 } //05 00  epl%d.exe
		$a_00_5 = {50 62 20 6f 66 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 2d 20 54 72 79 20 41 67 61 69 6e 20 3f } //01 00  Pb of connection - Try Again ?
		$a_00_6 = {53 63 72 69 70 74 56 69 73 69 6f } //01 00  ScriptVisio
		$a_00_7 = {69 66 20 65 78 25 73 20 22 25 73 22 20 67 6f 25 73 20 79 25 73 20 22 25 25 30 22 } //01 00  if ex%s "%s" go%s y%s "%%0"
		$a_00_8 = {53 70 65 61 6b 65 72 4d 6f 64 65 5f 44 69 61 6c } //00 00  SpeakerMode_Dial
	condition:
		any of ($a_*)
 
}