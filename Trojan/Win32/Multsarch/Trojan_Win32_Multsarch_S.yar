
rule Trojan_Win32_Multsarch_S{
	meta:
		description = "Trojan:Win32/Multsarch.S,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 74 00 2e 00 73 00 74 00 69 00 6d 00 75 00 6c 00 70 00 72 00 6f 00 66 00 69 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 6f 00 66 00 74 00 5f 00 65 00 78 00 65 00 63 00 2e 00 70 00 68 00 70 00 } //01 00  ext.stimulprofit.com/soft_exec.php
		$a_01_1 = {61 00 3d 00 72 00 61 00 74 00 65 00 73 00 26 00 6e 00 75 00 6d 00 3d 00 } //01 00  a=rates&num=
		$a_01_2 = {68 00 65 00 6c 00 70 00 40 00 7a 00 65 00 72 00 6f 00 67 00 72 00 61 00 76 00 69 00 74 00 79 00 2e 00 6b 00 7a 00 } //01 00  help@zerogravity.kz
		$a_01_3 = {5a 00 65 00 72 00 6f 00 20 00 47 00 72 00 61 00 76 00 69 00 74 00 79 00 } //01 00  Zero Gravity
		$a_01_4 = {23 23 23 54 4f 52 52 45 4e 54 32 45 58 45 23 23 23 } //00 00  ###TORRENT2EXE###
	condition:
		any of ($a_*)
 
}