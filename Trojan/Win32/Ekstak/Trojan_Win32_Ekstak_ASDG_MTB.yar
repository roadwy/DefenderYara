
rule Trojan_Win32_Ekstak_ASDG_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 56 57 68 88 32 65 00 e8 c0 62 fb ff e9 } //1
		$a_01_1 = {44 3a 5c 43 4f 4c 4f 52 52 45 46 5c 70 61 6c 6c 65 74 31 31 37 31 2e 70 6c 74 } //1 D:\COLORREF\pallet1171.plt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}