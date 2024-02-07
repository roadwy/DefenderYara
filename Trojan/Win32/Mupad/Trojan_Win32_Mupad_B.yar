
rule Trojan_Win32_Mupad_B{
	meta:
		description = "Trojan:Win32/Mupad.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6c 65 61 74 68 65 72 72 6f 70 65 2e 74 6f 70 2f 69 6e 64 65 78 2e 68 74 6d } //02 00  http://leatherrope.top/index.htm
		$a_01_1 = {2f 2f 74 68 72 65 61 74 65 6e 68 69 67 68 77 61 79 2e 72 75 2f 69 6e 64 65 78 2e 68 74 6d } //02 00  //threatenhighway.ru/index.htm
		$a_01_2 = {3a 2f 2f 74 6f 75 72 6a 65 72 6b 70 69 67 2e 72 75 2f 69 6e 64 65 78 2e 68 74 6d } //01 00  ://tourjerkpig.ru/index.htm
		$a_01_3 = {2f 69 6e 64 65 78 2e 68 74 6d 3b 63 72 79 70 74 3d 32 35 37 30 3b 67 2e 70 75 72 65 63 6f 6e 74 69 6e 75 65 2e 72 75 } //00 00  /index.htm;crypt=2570;g.purecontinue.ru
	condition:
		any of ($a_*)
 
}