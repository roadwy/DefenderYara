
rule TrojanSpy_Win32_Bancos_ADW{
	meta:
		description = "TrojanSpy:Win32/Bancos.ADW,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 65 00 61 00 69 00 72 00 63 00 65 00 6c 00 6c 00 65 00 37 00 36 00 2e 00 6f 00 72 00 67 00 2f 00 32 00 2e 00 70 00 68 00 70 00 3f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 6b 00 6c 00 76 00 61 00 72 00 3d 00 31 00 } //02 00  http://ceaircelle76.org/2.php?configklvar=1
		$a_01_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2d 00 66 00 20 00 2d 00 69 00 6d 00 } //00 00  taskkill -f -im
	condition:
		any of ($a_*)
 
}