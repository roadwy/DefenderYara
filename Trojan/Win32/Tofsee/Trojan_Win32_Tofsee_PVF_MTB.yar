
rule Trojan_Win32_Tofsee_PVF_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 fe 9c 19 00 00 7d 90 01 01 6a 00 6a 00 ff d3 e8 90 01 04 30 04 37 83 ee 01 79 90 00 } //2
		$a_02_1 = {81 ff 12 23 00 00 7d 90 01 01 6a 00 ff 15 90 01 04 8b 74 24 0c e8 90 01 04 30 04 3e 4f 79 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}