
rule Trojan_Win32_Offloader_L_MTB{
	meta:
		description = "Trojan:Win32/Offloader.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 00 56 00 45 00 52 00 59 00 53 00 49 00 4c 00 45 00 4e 00 54 00 } //02 00  /VERYSILENT
		$a_01_1 = {2f 00 53 00 55 00 50 00 50 00 52 00 45 00 53 00 53 00 4d 00 53 00 47 00 42 00 4f 00 58 00 45 00 53 00 } //02 00  /SUPPRESSMSGBOXES
		$a_01_2 = {7b 00 74 00 6d 00 70 00 7d 00 5c 00 63 00 68 00 65 00 63 00 6b 00 } //02 00  {tmp}\check
		$a_01_3 = {2f 00 72 00 6c 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 66 00 7a 00 3d 00 } //02 00  /rlo.php?fz=
		$a_01_4 = {2f 00 79 00 65 00 74 00 2e 00 70 00 68 00 70 00 3f 00 70 00 61 00 77 00 3d 00 } //02 00  /yet.php?paw=
		$a_01_5 = {2f 00 74 00 72 00 61 00 63 00 6b 00 65 00 72 00 2f 00 74 00 68 00 61 00 6e 00 6b 00 5f 00 79 00 6f 00 75 00 2e 00 70 00 68 00 70 00 3f 00 74 00 72 00 6b 00 3d 00 } //00 00  /tracker/thank_you.php?trk=
	condition:
		any of ($a_*)
 
}