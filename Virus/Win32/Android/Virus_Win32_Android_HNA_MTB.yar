
rule Virus_Win32_Android_HNA_MTB{
	meta:
		description = "Virus:Win32/Android.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 00 00 8d 45 f4 50 8d 95 70 ff ff ff b9 80 00 00 00 8b c7 } //1
		$a_01_1 = {2e 65 78 65 00 00 00 00 53 61 6c 75 74 20 44 65 } //1
		$a_03_2 = {c6 00 02 ff 36 68 ?? ?? ?? ?? 8b c3 33 d2 52 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}