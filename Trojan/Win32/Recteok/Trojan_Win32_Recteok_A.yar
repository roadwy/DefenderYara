
rule Trojan_Win32_Recteok_A{
	meta:
		description = "Trojan:Win32/Recteok.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 36 33 30 36 36 33 30 36 36 33 30 37 31 33 37 } //1 6630663066307137
		$a_01_1 = {35 33 37 37 35 33 37 37 35 33 37 37 37 44 46 34 } //1 5377537753777DF4
		$a_01_2 = {34 35 35 34 34 35 35 34 34 38 33 36 } //1 455445544836
		$a_01_3 = {7c 30 7c 00 ff ff ff ff 03 00 00 00 47 4f 54 00 ff ff ff ff 06 00 00 00 67 72 61 76 61 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}