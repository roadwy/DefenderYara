
rule Trojan_Win32_Offloader_D_MTB{
	meta:
		description = "Trojan:Win32/Offloader.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 73 00 69 00 6e 00 6b 00 6c 00 69 00 6e 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 6c 00 6d 00 6b 00 2e 00 70 00 68 00 70 00 3f 00 } //02 00  ://sinkline.xyz/lmk.php?
		$a_01_1 = {2e 00 78 00 79 00 7a 00 2f 00 6c 00 6f 00 6b 00 2e 00 70 00 68 00 70 00 3f 00 } //02 00  .xyz/lok.php?
		$a_01_2 = {2d 00 2d 00 73 00 69 00 6c 00 65 00 6e 00 74 00 20 00 2d 00 2d 00 61 00 6c 00 6c 00 75 00 73 00 65 00 72 00 73 00 3d 00 } //00 00  --silent --allusers=
	condition:
		any of ($a_*)
 
}