
rule Trojan_Win32_Azorult_OF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f6 39 1d [0-06] 8b [0-05] 8b [0-05] 8a [0-06] 8b [0-05] 88 [0-02] 81 3d [0-08] 75 } //1
		$a_02_1 = {33 f6 39 1d [0-04] 90 18 e8 [0-04] e8 [0-04] 8b [0-05] 8b [0-05] 33 f6 eb } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}