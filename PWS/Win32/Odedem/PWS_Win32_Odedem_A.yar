
rule PWS_Win32_Odedem_A{
	meta:
		description = "PWS:Win32/Odedem.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {f6 c3 01 c6 02 00 74 2a bf ?? ?? ?? ?? 83 c9 ff } //2
		$a_03_1 = {83 c9 02 eb 3e 68 ?? ?? ?? ?? 55 e8 ?? ?? 00 00 83 c4 08 85 c0 74 0e 8b 84 24 ?? ?? 00 00 8b 08 83 c9 04 eb 1e } //2
		$a_01_2 = {6c 3d 25 73 26 70 3d 25 73 26 77 3d 25 73 } //1 l=%s&p=%s&w=%s
		$a_01_3 = {63 3d 30 26 77 3d 6e 6f 6e 65 } //1 c=0&w=none
		$a_01_4 = {63 3d 31 26 77 3d 25 73 } //1 c=1&w=%s
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}