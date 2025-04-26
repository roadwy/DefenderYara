
rule Trojan_BAT_Formbook_DD_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {00 06 07 16 20 ?? ?? ?? ?? 6f ?? ?? ?? ?? 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? ?? ?? ?? ?? ?? 16 fe 02 13 05 11 05 2d } //10
		$a_80_1 = {47 5a 49 44 45 4b 4b 4b 4b } //GZIDEKKKK  1
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}
rule Trojan_BAT_Formbook_DD_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 62 39 38 36 64 63 37 35 2d 63 35 32 34 2d 34 33 62 33 2d 39 64 30 36 2d 62 61 34 36 30 63 38 66 65 64 66 35 } //1 $b986dc75-c524-43b3-9d06-ba460c8fedf5
		$a_81_1 = {43 61 70 74 75 72 65 53 63 72 65 65 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 CaptureScreen.Properties.Resources
		$a_81_2 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_3 = {43 61 70 74 75 72 65 20 6d 6f 75 73 65 20 63 75 72 73 6f 72 } //1 Capture mouse cursor
		$a_81_4 = {42 61 63 6b 67 72 6f 75 6e 64 57 6f 72 6b 65 72 } //1 BackgroundWorker
		$a_81_5 = {6b 72 79 70 74 6f 6e 42 75 74 74 6f 6e } //1 kryptonButton
		$a_81_6 = {53 6f 6e 69 63 4d 61 73 74 65 72 } //1 SonicMaster
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}