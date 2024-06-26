
rule VirTool_Win32_Obfuscator_AV{
	meta:
		description = "VirTool:Win32/Obfuscator.AV,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe8 03 50 00 1f 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 54 6d 70 4d 61 70 } //02 00  ShellTmpMap
		$a_01_1 = {44 65 43 72 79 70 74 } //02 00  DeCrypt
		$a_01_2 = {45 6e 43 72 79 70 74 } //02 00  EnCrypt
		$a_01_3 = {54 65 73 74 42 6d 70 } //02 00  TestBmp
		$a_01_4 = {54 65 73 74 44 65 62 75 67 } //02 00  TestDebug
		$a_01_5 = {49 6f 66 43 6f 6d 70 6c 65 74 65 52 65 71 75 65 73 74 } //02 00  IofCompleteRequest
		$a_01_6 = {4d 6d 49 73 41 64 64 72 65 73 73 56 61 6c 69 64 } //02 00  MmIsAddressValid
		$a_01_7 = {49 6f 43 72 65 61 74 65 44 65 76 69 63 65 } //02 00  IoCreateDevice
		$a_01_8 = {49 6f 43 72 65 61 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b } //02 00  IoCreateSymbolicLink
		$a_01_9 = {49 6f 44 65 6c 65 74 65 44 65 76 69 63 65 } //02 00  IoDeleteDevice
		$a_01_10 = {49 6f 44 65 6c 65 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b } //02 00  IoDeleteSymbolicLink
		$a_01_11 = {52 74 6c 49 6e 69 74 55 6e 69 63 6f 64 65 53 74 72 69 6e 67 } //02 00  RtlInitUnicodeString
		$a_01_12 = {40 49 4e 49 54 } //04 00  @INIT
		$a_01_13 = {63 61 6e 20 6e 6f 74 20 66 6f 75 6e 64 20 25 73 } //02 00  can not found %s
		$a_01_14 = {46 75 6e 63 32 46 75 6e 63 } //02 00  Func2Func
		$a_01_15 = {53 68 65 6c 6c 4d 61 70 } //01 00  ShellMap
		$a_01_16 = {77 61 72 6e 69 6e 67 } //01 00  warning
		$a_01_17 = {2e 72 65 6c 6f 63 } //02 00  .reloc
		$a_01_18 = {64 6f 6e 74 20 70 61 6e 69 63 } //02 00  dont panic
		$a_01_19 = {2d 66 6f 49 31 } //05 00  -foI1
		$a_01_20 = {72 69 6e 67 30 20 6d 6f 64 75 6c 65 } //05 00  ring0 module
		$a_01_21 = {5c 5c 2e 5c 72 69 6e 67 30 } //05 00  \\.\ring0
		$a_00_22 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 72 00 69 00 6e 00 67 00 30 00 } //05 00  \DosDevices\ring0
		$a_00_23 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 72 00 69 00 6e 00 67 00 30 00 } //05 00  \Device\ring0
		$a_01_24 = {72 69 6e 67 30 2e 73 79 73 } //05 00  ring0.sys
		$a_01_25 = {58 44 4c 4c 2e 44 4c 4c } //02 00  XDLL.DLL
		$a_01_26 = {6d 79 64 72 76 } //02 00  mydrv
		$a_01_27 = {78 77 67 66 65 } //02 00  xwgfe
		$a_01_28 = {5c 24 48 5c 24 58 } //02 00  \$H\$X
		$a_01_29 = {4e 6e 6f 65 33 } //02 00  Nnoe3
		$a_01_30 = {4e 54 4f 53 4b 52 4e 4c 2e 45 58 45 } //00 00  NTOSKRNL.EXE
	condition:
		any of ($a_*)
 
}