
rule Trojan_Win32_Vodvit_B{
	meta:
		description = "Trojan:Win32/Vodvit.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {b2 6c b3 6f b9 34 00 00 00 33 c0 8d bc 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? c6 84 24 ?? ?? ?? ?? 64 } //1
		$a_01_1 = {61 75 5f 75 70 64 61 74 61 2e 65 78 65 } //1 au_updata.exe
		$a_01_2 = {61 75 63 6f 64 65 5f 31 39 39 32 5f 30 39 31 35 } //1 aucode_1992_0915
		$a_01_3 = {61 75 6c 69 73 74 2e 74 78 74 } //1 aulist.txt
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}