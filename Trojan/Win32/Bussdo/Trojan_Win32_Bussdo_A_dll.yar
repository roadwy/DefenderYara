
rule Trojan_Win32_Bussdo_A_dll{
	meta:
		description = "Trojan:Win32/Bussdo.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 eb 2a 80 f9 0d 75 1d 80 bc 05 90 01 01 f9 ff ff 0a 75 13 38 8c 05 90 01 01 f9 ff ff 75 0a 80 bc 05 90 00 } //1
		$a_02_1 = {59 99 b9 e9 03 00 00 f7 f9 81 c2 e8 03 00 00 52 ff d6 66 89 45 90 01 01 8d 45 90 01 01 50 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}