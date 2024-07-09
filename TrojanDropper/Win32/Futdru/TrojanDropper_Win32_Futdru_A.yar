
rule TrojanDropper_Win32_Futdru_A{
	meta:
		description = "TrojanDropper:Win32/Futdru.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {ab 8d 45 d0 33 ff 2b c8 8d 44 3d d0 8a 14 01 80 f2 af 47 83 ff 09 88 10 7c ee } //1
		$a_03_1 = {11 83 c4 1c 81 c7 ?? ?? 00 00 b9 99 00 00 00 6a 04 80 77 03 19 58 3b cb 75 0d 8a 0c 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}