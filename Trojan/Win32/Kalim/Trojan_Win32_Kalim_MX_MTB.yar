
rule Trojan_Win32_Kalim_MX_MTB{
	meta:
		description = "Trojan:Win32/Kalim.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 ff 15 88 a1 ?? 00 89 45 d8 85 c0 75 24 } //1
		$a_00_1 = {77 21 0f b6 c1 46 83 e8 30 66 0f 6e c0 8a 06 f3 0f e6 c0 f2 0f 59 c2 f2 0f 59 d4 f2 0f 58 c8 3c 30 7d d8 3c 65 } //1
		$a_00_2 = {6b 61 6c 69 6d } //5 kalim
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*5) >=6
 
}