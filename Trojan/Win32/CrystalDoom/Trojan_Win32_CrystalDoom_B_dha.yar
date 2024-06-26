
rule Trojan_Win32_CrystalDoom_B_dha{
	meta:
		description = "Trojan:Win32/CrystalDoom.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 22 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6d 70 6f 72 74 20 54 73 } //01 00  import Ts
		$a_01_1 = {64 65 66 20 74 73 5f } //01 00  def ts_
		$a_01_2 = {54 53 5f 63 6e 61 6d 65 73 2e 70 79 } //01 00  TS_cnames.py
		$a_01_3 = {54 52 49 43 4f 4e } //01 00  TRICON
		$a_01_4 = {54 72 69 53 74 61 74 69 6f 6e 20 } //01 00  TriStation 
		$a_01_5 = {20 63 68 61 73 73 69 73 20 } //01 00   chassis 
		$a_01_6 = {47 65 74 43 70 53 74 61 74 75 73 } //01 00  GetCpStatus
		$a_01_7 = {69 6d 70 6f 72 74 20 54 73 48 69 } //01 00  import TsHi
		$a_01_8 = {69 6d 70 6f 72 74 20 54 73 4c 6f 77 } //01 00  import TsLow
		$a_01_9 = {69 6d 70 6f 72 74 20 54 73 42 61 73 65 } //01 00  import TsBase
		$a_03_10 = {6d 6f 64 75 6c 65 90 01 01 76 65 72 73 69 6f 6e 90 00 } //01 00 
		$a_01_11 = {70 72 6f 67 5f 63 6e 74 } //01 00  prog_cnt
		$a_01_12 = {54 73 42 61 73 65 2e 70 79 } //01 00  TsBase.py
		$a_01_13 = {2e 54 73 42 61 73 65 28 } //01 00  .TsBase(
		$a_01_14 = {54 73 48 69 2e 70 79 } //01 00  TsHi.py
		$a_01_15 = {6b 65 79 73 74 61 74 65 } //01 00  keystate
		$a_01_16 = {47 65 74 50 72 6f 6a 65 63 74 49 6e 66 6f } //01 00  GetProjectInfo
		$a_01_17 = {47 65 74 50 72 6f 67 72 61 6d 54 61 62 6c 65 } //01 00  GetProgramTable
		$a_01_18 = {53 61 66 65 41 70 70 65 6e 64 50 72 6f 67 72 61 6d 4d 6f 64 } //01 00  SafeAppendProgramMod
		$a_01_19 = {2e 54 73 48 69 28 } //01 00  .TsHi(
		$a_01_20 = {54 73 4c 6f 77 2e 70 79 } //01 00  TsLow.py
		$a_01_21 = {70 72 69 6e 74 5f 6c 61 73 74 5f 65 72 72 6f 72 } //01 00  print_last_error
		$a_01_22 = {2e 54 73 4c 6f 77 28 } //01 00  .TsLow(
		$a_01_23 = {20 54 43 4d 20 66 6f 75 6e 64 } //01 00   TCM found
		$a_01_24 = {43 52 43 31 36 5f 4d 4f 44 42 55 53 } //01 00  CRC16_MODBUS
		$a_01_25 = {4b 6f 74 6f 76 20 41 6c 61 78 61 6e 64 65 72 } //01 00  Kotov Alaxander
		$a_01_26 = {43 52 43 5f 43 43 49 54 54 5f 58 4d 4f 44 45 4d } //01 00  CRC_CCITT_XMODEM
		$a_01_27 = {63 72 63 31 36 72 65 74 } //01 00  crc16ret
		$a_01_28 = {43 52 43 31 36 5f 43 43 49 54 54 } //01 00  CRC16_CCITT
		$a_01_29 = {73 68 2e 70 79 63 } //01 00  sh.pyc
		$a_01_30 = {20 46 41 49 4c 55 52 45 } //01 00   FAILURE
		$a_01_31 = {73 79 6d 62 6f 6c 20 74 61 62 6c 65 } //01 00  symbol table
		$a_01_32 = {69 6e 6a 65 63 74 2e 62 69 6e } //01 00  inject.bin
		$a_01_33 = {69 6d 61 69 6e 2e 62 69 6e } //00 00  imain.bin
	condition:
		any of ($a_*)
 
}