
rule Trojan_Win32_Glupteba_OB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 04 1e 81 ff ?? ?? ?? ?? 90 18 46 3b f7 90 18 90 18 51 a1 [0-04] 69 [0-05] a3 [0-04] c7 [0-06] 81 [0-1a] 25 [0-05] c3 } //1
		$a_02_1 = {6a 00 6a 00 e8 [0-04] 46 3b ?? 90 18 e8 [0-04] 30 04 ?? 81 ff [0-04] 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}