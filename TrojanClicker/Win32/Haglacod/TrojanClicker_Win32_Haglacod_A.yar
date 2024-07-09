
rule TrojanClicker_Win32_Haglacod_A{
	meta:
		description = "TrojanClicker:Win32/Haglacod.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3f 61 3d 53 65 61 72 63 68 26 71 3d 00 } //1
		$a_01_1 = {2f 46 6c 61 73 68 } //1 /Flash
		$a_01_2 = {2f 69 6e 66 6f 2e 74 78 74 } //1 /info.txt
		$a_03_3 = {ba 27 02 00 00 8b 86 f8 02 00 00 e8 ?? ?? ?? ?? 8d 55 fc b8 1a 00 00 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}