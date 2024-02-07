
rule PWS_Win32_QQpass_CIA{
	meta:
		description = "PWS:Win32/QQpass.CIA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 3a 5c 73 79 73 2e 74 78 74 } //01 00  d:\sys.txt
		$a_01_1 = {64 3a 5c 54 78 73 2e 64 6c 6c } //01 00  d:\Txs.dll
		$a_01_2 = {6d 6d 32 30 32 30 2e 75 73 61 32 30 2e 63 65 73 68 69 36 2e 63 6f 6d 2f 53 50 4f 50 2f 44 58 42 50 56 51 2f 75 73 65 72 2e 61 73 70 3f 75 73 65 72 6e 61 6d 65 3d } //01 00  mm2020.usa20.ceshi6.com/SPOP/DXBPVQ/user.asp?username=
		$a_01_3 = {26 6f 70 5f 74 79 70 65 3d 61 64 64 26 73 75 62 6d 69 74 3d 6f 6b 00 26 61 32 3d 00 26 61 31 3d 00 26 70 61 73 73 77 6f 72 64 3d 00 } //00 00  漦彰祴数愽摤猦扵業㵴歯☀㉡=愦㴱☀慰獳潷摲=
	condition:
		any of ($a_*)
 
}