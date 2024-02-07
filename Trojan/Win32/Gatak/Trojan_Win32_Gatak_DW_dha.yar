
rule Trojan_Win32_Gatak_DW_dha{
	meta:
		description = "Trojan:Win32/Gatak.DW!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 4e 54 4b 4c 5f 4e 44 54 5f 53 54 41 54 55 53 5f 50 57 44 5f 54 47 54 5f 52 55 4e 4e 49 4e 53 55 46 46 4c 52 57 4e } //01 00  INTKL_NDT_STATUS_PWD_TGT_RUNNINSUFFLRWN
		$a_01_1 = {55 4c 5f 55 4e 52 4b 41 43 4f 4e 4e 43 4c 5f 53 58 41 4b 55 53 5f 47 4f 44 5f 44 46 4c 59 53 59 } //01 00  UL_UNRKACONNCL_SXAKUS_GOD_DFLYSY
		$a_01_2 = {53 54 41 54 4e 53 5f 59 54 4f 33 32 2e 64 6c 6c } //01 00  STATNS_YTO32.dll
		$a_01_3 = {54 41 53 5f 43 4c 53 53 45 5f 4e 55 54 5f 33 } //02 00  TAS_CLSSE_NUT_3
		$a_01_4 = {41 4d 54 5f 53 45 52 56 45 52 5f 44 45 54 } //02 00  AMT_SERVER_DET
		$a_01_5 = {4d 6f 64 75 6c 74 73 4e 6f 75 6e 64 } //04 00  ModultsNound
		$a_01_6 = {6d 63 63 69 77 68 2e 73 79 73 64 69 72 } //02 00  mcciwh.sysdir
		$a_01_7 = {6d 63 63 74 63 6d 2e 73 79 73 79 73 72 } //02 00  mcctcm.sysysr
		$a_01_8 = {52 78 3a 20 44 68 66 66 65 72 20 44 61 73 61 } //02 00  Rx: Dhffer Dasa
		$a_01_9 = {4d 69 63 72 6f 73 6f 66 74 5c 53 48 56 55 5c 6a 6c 74 6c 65 } //00 00  Microsoft\SHVU\jltle
		$a_00_10 = {5d 04 00 00 } //b4 3c 
	condition:
		any of ($a_*)
 
}