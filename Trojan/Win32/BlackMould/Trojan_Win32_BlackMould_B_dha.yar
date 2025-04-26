
rule Trojan_Win32_BlackMould_B_dha{
	meta:
		description = "Trojan:Win32/BlackMould.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {30 36 32 38 31 38 32 30 31 36 31 33 34 38 30 35 31 34 33 33 31 32 } //3 0628182016134805143312
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 2e 53 6f 66 74 } //2 Microsoft.Soft
		$a_01_2 = {5b 43 68 65 63 6b 56 61 6c 75 65 5d 3a } //2 [CheckValue]:
		$a_01_3 = {73 72 76 68 74 74 70 2e 6c 6f 67 } //1 srvhttp.log
		$a_01_4 = {45 52 52 4f 52 3a 2f 2f } //1 ERROR://
		$a_01_5 = {52 65 6e 61 6d 65 20 46 69 6c 65 20 46 61 69 6c 2e } //1 Rename File Fail.
		$a_01_6 = {68 65 6c 6c 6f 21 21 21 } //1 hello!!!
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}