
rule Trojan_Win32_Offloader_K_MTB{
	meta:
		description = "Trojan:Win32/Offloader.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 00 56 00 45 00 52 00 59 00 53 00 49 00 4c 00 45 00 4e 00 54 00 } //2 /VERYSILENT
		$a_01_1 = {2f 00 53 00 55 00 50 00 50 00 52 00 45 00 53 00 53 00 4d 00 53 00 47 00 42 00 4f 00 58 00 45 00 53 00 } //2 /SUPPRESSMSGBOXES
		$a_01_2 = {7b 00 74 00 6d 00 70 00 7d 00 5c 00 63 00 68 00 65 00 63 00 6b 00 } //2 {tmp}\check
		$a_01_3 = {2f 00 73 00 64 00 66 00 2e 00 70 00 68 00 70 00 3f 00 70 00 69 00 64 00 3d 00 } //2 /sdf.php?pid=
		$a_01_4 = {2f 00 74 00 72 00 61 00 63 00 6b 00 65 00 72 00 2f 00 74 00 68 00 61 00 6e 00 6b 00 5f 00 79 00 6f 00 75 00 2e 00 70 00 68 00 70 00 3f 00 74 00 72 00 6b 00 3d 00 } //2 /tracker/thank_you.php?trk=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}