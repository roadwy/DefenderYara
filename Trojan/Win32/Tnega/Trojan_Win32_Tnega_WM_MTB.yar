
rule Trojan_Win32_Tnega_WM_MTB{
	meta:
		description = "Trojan:Win32/Tnega.WM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {31 16 81 c6 04 00 00 00 4f 81 e9 ?? ?? ?? ?? 39 c6 75 e8 c3 14 40 00 c3 29 fb 39 db 74 01 } //10
		$a_02_1 = {31 07 09 d1 81 eb ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 39 f7 75 e7 c3 81 c3 f7 23 8e 2b ff 21 f2 39 c3 75 e5 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=10
 
}