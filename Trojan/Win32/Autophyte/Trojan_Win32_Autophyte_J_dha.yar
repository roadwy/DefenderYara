
rule Trojan_Win32_Autophyte_J_dha{
	meta:
		description = "Trojan:Win32/Autophyte.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 22 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6f 63 6b 74 65 } //01 00  sockte
		$a_01_1 = {63 6c 6f 73 74 73 6f 63 6b 74 65 } //01 00  clostsockte
		$a_01_2 = {63 6f 6e 6e 74 63 65 } //01 00  conntce
		$a_01_3 = {76 74 65 77 6f 73 65 62 6a 6e 61 6d 74 } //01 00  vtewosebjnamt
		$a_01_4 = {73 77 66 65 64 6f 68 6e } //01 00  swfedohn
		$a_01_5 = {6c 78 73 65 74 6e } //01 00  lxsetn
		$a_01_6 = {57 53 41 53 65 61 72 65 66 70 } //01 00  WSASearefp
		$a_01_7 = {73 74 65 73 6f 63 6b 6f 70 65 } //01 00  stesockope
		$a_01_8 = {57 53 41 43 6c 74 61 6e 66 70 } //01 00  WSACltanfp
		$a_01_9 = {47 74 65 44 72 78 67 74 54 6a 70 74 41 } //01 00  GteDrxgtTjptA
		$a_01_10 = {56 78 72 65 66 61 6c 51 66 74 72 6a 45 69 } //01 00  VxrefalQftrjEi
		$a_01_11 = {43 72 74 61 65 74 46 78 6c 74 4d 61 70 70 78 6e 76 41 } //01 00  CrtaetFxltMappxnvA
		$a_01_12 = {46 78 6e 64 43 6c 6f 73 74 } //01 00  FxndClost
		$a_01_13 = {4d 6f 67 74 46 78 6c 74 45 69 41 } //01 00  MogtFxltEiA
		$a_01_14 = {47 74 65 4d 6f 64 66 6c 74 48 61 6e 64 6c 74 41 } //01 00  GteModfltHandltA
		$a_01_15 = {46 78 6e 64 4e 74 69 65 46 78 6c 74 41 } //01 00  FxndNtieFxltA
		$a_01_16 = {47 74 65 43 6f 6d 70 66 65 74 72 4e 61 6d 74 41 } //01 00  GteCompfetrNamtA
		$a_01_17 = {57 72 78 65 74 50 72 6f 63 74 73 73 4d 74 6d 6f 72 6a } //01 00  WrxetProctssMtmorj
		$a_01_18 = {56 78 72 65 66 61 6c 50 72 6f 65 74 63 65 45 69 } //01 00  VxrefalProetceEi
		$a_01_19 = {46 72 74 74 4c 78 62 72 61 72 6a } //01 00  FrttLxbrarj
		$a_01_20 = {54 74 72 6d 78 6e 61 65 74 50 72 6f 63 74 73 73 } //01 00  TtrmxnaetProctss
		$a_01_21 = {43 72 74 61 65 74 46 78 6c 74 41 } //01 00  CrtaetFxltA
		$a_01_22 = {4f 70 74 6e 50 72 6f 63 74 73 73 } //01 00  OptnProctss
		$a_01_23 = {47 74 65 4c 6f 76 78 63 61 6c 44 72 78 67 74 73 } //01 00  GteLovxcalDrxgts
		$a_01_24 = {53 74 65 46 78 6c 74 54 78 6d 74 } //01 00  SteFxltTxmt
		$a_01_25 = {47 74 65 56 74 72 73 78 6f 6e 45 69 41 } //01 00  GteVtrsxonEiA
		$a_01_26 = {55 6e 6d 61 70 56 78 74 68 4f 75 46 78 6c 74 } //01 00  UnmapVxthOuFxlt
		$a_01_27 = {47 74 65 43 66 72 72 74 6e 65 50 72 6f 63 74 73 73 } //01 00  GteCfrrtneProctss
		$a_01_28 = {47 74 65 53 6a 73 65 74 6d 44 78 72 74 63 65 6f 72 6a 41 } //01 00  GteSjsetmDxrtceorjA
		$a_01_29 = {47 74 65 4c 6f 63 61 6c 54 78 6d 74 } //01 00  GteLocalTxmt
		$a_01_30 = {43 72 74 61 65 74 50 72 6f 63 74 73 73 41 } //01 00  CrtaetProctssA
		$a_01_31 = {47 74 65 54 74 6d 70 50 61 65 77 41 } //01 00  GteTtmpPaewA
		$a_01_32 = {43 72 74 61 65 74 54 6f 6f 6c 77 74 6c 70 33 32 53 6e 61 70 73 77 6f 65 } //01 00  CrtaetToolwtlp32Snapswoe
		$a_01_33 = {47 74 65 46 78 6c 74 41 65 65 72 78 62 66 65 74 73 41 } //00 00  GteFxltAeerxbfetsA
	condition:
		any of ($a_*)
 
}