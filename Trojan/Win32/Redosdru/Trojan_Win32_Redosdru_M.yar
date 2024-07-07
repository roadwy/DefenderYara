
rule Trojan_Win32_Redosdru_M{
	meta:
		description = "Trojan:Win32/Redosdru.M,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 80 04 11 90 01 01 90 02 10 8b 55 fc 80 34 11 90 01 01 90 02 10 41 3b c8 7c 90 00 } //2
		$a_01_1 = {50 43 52 61 74 20 55 70 64 61 74 65 } //1 PCRat Update
		$a_02_2 = {25 73 5c 64 6c 6c 63 61 63 68 65 5c 25 73 90 02 05 25 73 2e 64 6c 6c 90 00 } //1
		$a_01_3 = {50 43 52 61 74 53 74 61 63 74 } //1 PCRatStact
		$a_00_4 = {25 73 5c 25 64 5f 72 65 73 2e 74 6d 70 } //1 %s\%d_res.tmp
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}