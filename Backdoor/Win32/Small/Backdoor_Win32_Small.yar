
rule Backdoor_Win32_Small{
	meta:
		description = "Backdoor:Win32/Small,SIGNATURE_TYPE_PEHSTR_EXT,77 00 75 00 0f 00 00 32 00 "
		
	strings :
		$a_00_0 = {64 72 69 76 65 72 73 5c 73 79 73 74 65 6d 2e 65 78 65 } //32 00  drivers\system.exe
		$a_02_1 = {68 74 74 70 3a 2f 2f 61 72 70 2e 31 38 31 38 90 04 02 03 30 2d 39 2e 63 6e 2f 61 72 70 2e 68 74 6d 90 00 } //02 00 
		$a_00_2 = {72 6f 76 65 72 } //02 00  rover
		$a_00_3 = {77 70 63 61 70 2e 64 6c 6c } //02 00  wpcap.dll
		$a_00_4 = {6d 79 65 78 65 } //02 00  myexe
		$a_00_5 = {64 72 69 76 65 72 73 5c 6e 70 66 2e 73 79 73 } //02 00  drivers\npf.sys
		$a_00_6 = {50 61 63 6b 65 74 2e 64 6c 6c } //02 00  Packet.dll
		$a_00_7 = {57 61 6e 50 61 63 6b 65 74 2e 64 6c 6c } //02 00  WanPacket.dll
		$a_00_8 = {5f 64 65 6c 65 74 65 6d 65 2e 62 61 74 } //02 00  _deleteme.bat
		$a_00_9 = {3a 74 72 79 } //02 00  :try
		$a_00_10 = {69 66 20 20 20 65 78 69 73 74 } //01 00  if   exist
		$a_00_11 = {2d 70 6f 72 74 20 38 30 20 2d 69 6e 73 65 72 74 } //01 00  -port 80 -insert
		$a_00_12 = {2d 69 64 78 20 30 20 2d 69 70 } //01 00  -idx 0 -ip
		$a_00_13 = {2d 69 64 78 20 31 20 2d 69 70 } //01 00  -idx 1 -ip
		$a_00_14 = {2d 69 64 78 20 32 20 2d 69 70 20 20 6f 70 65 6e } //00 00  -idx 2 -ip  open
	condition:
		any of ($a_*)
 
}