
rule Trojan_Win32_Banker_MV_MTB{
	meta:
		description = "Trojan:Win32/Banker.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 64 70 72 6f 74 6f 6e } //1 wdproton
		$a_01_1 = {a1 64 a6 45 00 a3 6c 8d 45 00 68 5c 8d 45 00 e8 34 52 fb ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}