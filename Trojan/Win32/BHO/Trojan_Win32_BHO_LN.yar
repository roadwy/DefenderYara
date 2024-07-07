
rule Trojan_Win32_BHO_LN{
	meta:
		description = "Trojan:Win32/BHO.LN,SIGNATURE_TYPE_PEHSTR,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 6f 8f f6 4e e5 5d 0b 7a 5c 00 62 00 68 00 6f 00 5c 00 } //4
		$a_01_1 = {69 65 75 70 64 61 74 65 2e 64 6c 6c } //1 ieupdate.dll
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}