
rule Trojan_Win32_Fareit_SM_MSR{
	meta:
		description = "Trojan:Win32/Fareit.SM!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b ca 99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 07 88 07 } //1
		$a_01_1 = {63 3a 54 53 65 4b 37 34 36 66 36 31 33 37 33 61 33 35 33 33 33 39 33 31 33 31 33 38 33 38 63 61 63 63 33 39 33 35 } //1 c:TSeK746f61373a35333931313838cacc3935
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}