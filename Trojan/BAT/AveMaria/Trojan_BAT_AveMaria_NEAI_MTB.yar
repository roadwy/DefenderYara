
rule Trojan_BAT_AveMaria_NEAI_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3a 00 3a 00 12 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 76 6c 45 64 69 74 6f 72 2e 41 41 41 41 41 41 41 41 41 41 41 2e 72 65 73 6f 75 72 63 65 73 } //04 00  LvlEditor.AAAAAAAAAAA.resources
		$a_01_1 = {67 65 74 5f 53 70 69 6b 65 73 42 65 67 69 6e } //04 00  get_SpikesBegin
		$a_01_2 = {67 65 74 5f 48 6f 74 65 6c 43 68 65 63 6b 5f 49 6e } //04 00  get_HotelCheck_In
		$a_01_3 = {67 65 74 5f 54 69 63 6b 73 50 65 72 53 65 63 6f 6e 64 } //04 00  get_TicksPerSecond
		$a_01_4 = {74 73 6d 69 44 65 6c 65 74 65 4d 6f 64 65 5f 43 6c 69 63 6b } //04 00  tsmiDeleteMode_Click
		$a_01_5 = {67 65 74 5f 46 75 63 68 73 69 61 } //04 00  get_Fuchsia
		$a_01_6 = {67 65 74 5f 50 6f 77 64 65 72 42 6c 75 65 } //04 00  get_PowderBlue
		$a_01_7 = {67 65 74 5f 42 6c 61 6e 63 68 65 64 41 6c 6d 6f 6e 64 } //04 00  get_BlanchedAlmond
		$a_01_8 = {67 65 74 5f 50 61 73 73 77 6f 72 64 32 5f } //03 00  get_Password2_
		$a_01_9 = {6d 75 73 69 63 56 4f 4c } //03 00  musicVOL
		$a_01_10 = {4a 25 47 49 45 } //03 00  J%GIE
		$a_01_11 = {4e 65 77 4b 75 6c 61 4c 65 76 65 6c } //03 00  NewKulaLevel
		$a_01_12 = {49 6e 63 6f 6d 69 6e 67 54 65 6c 65 70 6f 72 74 73 } //03 00  IncomingTeleports
		$a_01_13 = {48 61 6e 67 48 6f 61 5f } //03 00  HangHoa_
		$a_01_14 = {4c 6f 77 65 72 53 75 72 66 } //01 00  LowerSurf
		$a_01_15 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_16 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_17 = {76 34 2e 30 2e 33 30 33 31 39 } //00 00  v4.0.30319
	condition:
		any of ($a_*)
 
}