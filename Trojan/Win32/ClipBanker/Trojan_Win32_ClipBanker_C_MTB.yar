
rule Trojan_Win32_ClipBanker_C_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {4f 75 74 70 75 74 56 61 72 32 20 3d 20 31 39 41 6e 35 67 55 55 53 57 41 35 6a 55 62 65 7a 35 6b 58 44 32 69 6d 61 51 44 43 41 5a 36 33 72 58 } //01 00  OutputVar2 = 19An5gUUSWA5jUbez5kXD2imaQDCAZ63rX
		$a_81_1 = {46 69 6c 65 44 65 6c 65 74 65 2c 20 6e 72 2e 62 63 6e } //01 00  FileDelete, nr.bcn
		$a_81_2 = {43 6c 69 70 62 6f 61 72 64 20 3a 3d 20 52 65 67 45 78 52 65 70 6c 61 63 65 28 43 6c 69 70 62 6f 61 72 64 2c 20 22 5b 30 2d 39 5d 5b 30 2d 39 5d } //01 00  Clipboard := RegExReplace(Clipboard, "[0-9][0-9]
		$a_81_3 = {53 65 74 57 6f 72 6b 69 6e 67 44 69 72 2c 20 25 74 65 6d 70 25 } //00 00  SetWorkingDir, %temp%
	condition:
		any of ($a_*)
 
}