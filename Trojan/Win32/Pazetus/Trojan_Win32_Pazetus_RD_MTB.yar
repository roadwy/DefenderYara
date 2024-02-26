
rule Trojan_Win32_Pazetus_RD_MTB{
	meta:
		description = "Trojan:Win32/Pazetus.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {da 97 68 ce e7 6c ae f8 c6 dd 7a 51 f8 fb a0 9d 0c 14 8d 20 14 02 92 9c 6c 82 e8 cd 3d d0 e4 33 c9 c7 17 e2 01 18 ca fc 8a de de 75 9e 5a 06 d1 } //00 00 
	condition:
		any of ($a_*)
 
}