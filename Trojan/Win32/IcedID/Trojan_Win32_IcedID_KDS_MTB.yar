
rule Trojan_Win32_IcedID_KDS_MTB{
	meta:
		description = "Trojan:Win32/IcedID.KDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {31 d8 69 c0 db 02 03 00 a3 90 09 05 00 a1 } //2
		$a_02_1 = {8b f7 05 d0 18 68 01 2b f1 83 ee 2f a3 ?? ?? ?? ?? 66 89 35 90 09 07 00 66 89 35 } //2
		$a_00_2 = {8a 44 15 fc 32 04 0e 47 88 01 3b 7d 10 72 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2) >=2
 
}