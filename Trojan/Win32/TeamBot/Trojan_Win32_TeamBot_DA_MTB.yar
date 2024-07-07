
rule Trojan_Win32_TeamBot_DA_MTB{
	meta:
		description = "Trojan:Win32/TeamBot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 c1 e8 05 89 45 f0 8b 4d fc 33 db 33 4d f4 8b 45 f0 03 c2 89 4d fc 33 c1 c7 05 90 01 04 ee 3d ea f4 8b 0d 90 01 04 89 45 f0 81 f9 13 02 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}