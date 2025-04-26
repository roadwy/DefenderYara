
rule Backdoor_Win32_Poison_BU{
	meta:
		description = "Backdoor:Win32/Poison.BU,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {30 78 31 41 37 42 34 43 39 46 } //5 0x1A7B4C9F
		$a_01_1 = {50 ad 03 c2 50 ad 03 c2 5b 50 33 c0 8b 34 83 03 f2 } //1
		$a_01_2 = {b9 18 00 00 00 33 ff 33 c0 66 ad 85 c0 74 0d } //1
		$a_01_3 = {03 f2 53 50 33 db 33 c0 ac c1 c3 13 03 d8 83 f8 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}