
rule Trojan_Win32_Alureon_AP{
	meta:
		description = "Trojan:Win32/Alureon.AP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {7b 36 42 46 35 32 41 35 32 2d 33 39 34 41 2d 31 31 44 33 2d 42 31 35 33 2d 30 30 43 30 34 46 37 39 46 41 41 36 7d } //1 {6BF52A52-394A-11D3-B153-00C04F79FAA6}
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 47 49 47 41 50 6f 72 6e 00 } //1 潓瑦慷敲䝜䝉偁牯n
		$a_01_2 = {47 49 47 41 50 6f 72 6e 20 53 65 74 75 70 } //1 GIGAPorn Setup
		$a_01_3 = {69 6e 73 74 31 2e 65 78 65 } //1 inst1.exe
		$a_01_4 = {4c 49 43 45 4e 53 45 20 41 47 52 45 45 4d 45 4e 54 20 21 } //1 LICENSE AGREEMENT !
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}