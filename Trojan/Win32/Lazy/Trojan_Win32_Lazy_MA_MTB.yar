
rule Trojan_Win32_Lazy_MA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {b9 04 01 00 00 66 5b 66 83 fb 00 74 0a 66 81 eb f7 00 88 1f 47 e2 ee 66 59 52 c3 } //1
		$a_01_1 = {54 79 59 69 } //5 TyYi
		$a_01_2 = {64 6c 76 72 2e 64 6c 6c } //2 dlvr.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2) >=8
 
}