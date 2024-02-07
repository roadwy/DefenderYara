
rule Backdoor_Win32_Koceg_gen_C{
	meta:
		description = "Backdoor:Win32/Koceg.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0a 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 fc 83 7d fc ff 75 04 33 c0 eb 03 6a 01 58 } //03 00 
		$a_01_1 = {39 45 fc 7d 16 8b 45 08 03 45 fc 0f be 00 33 45 0c 8b 4d 08 03 4d fc 88 01 eb d5 8b 45 08 } //03 00 
		$a_01_2 = {39 45 fc 7d 25 8b 45 08 03 45 fc 0f be 00 83 f8 30 7c 0e 8b 45 08 03 45 fc 0f be 00 83 f8 39 7e 07 } //03 00 
		$a_01_3 = {8b 4d 08 0f b6 44 01 f8 83 e8 30 69 c0 80 96 98 00 8b 4d fc 03 c8 89 4d fc 8b 45 fc } //03 00 
		$a_01_4 = {59 99 b9 30 75 00 00 f7 f9 } //03 00 
		$a_03_5 = {ff 33 27 00 00 74 05 e9 90 01 01 00 00 00 6a 00 68 e8 03 00 00 8d 85 90 00 } //01 00 
		$a_01_6 = {6f 63 30 63 68 67 30 3a 2c 72 6a 72 } //01 00  oc0chg0:,rjr
		$a_01_7 = {67 7a 72 6e 6d 70 67 70 2c 66 6e 6e } //01 00  gzrnmpgp,fnn
		$a_01_8 = {23 53 6e 69 66 66 } //01 00  #Sniff
		$a_01_9 = {26 65 6d 61 69 6c 73 3d } //01 00  &emails=
		$a_01_10 = {26 63 69 70 3d 00 } //01 00  挦灩=
		$a_01_11 = {26 6c 69 64 3d 00 } //00 00  氦摩=
	condition:
		any of ($a_*)
 
}