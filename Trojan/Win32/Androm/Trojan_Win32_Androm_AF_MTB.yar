
rule Trojan_Win32_Androm_AF_MTB{
	meta:
		description = "Trojan:Win32/Androm.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 52 50 8b c3 [0-04] 03 [0-04] 13 54 [0-04] 71 ?? e8 [0-04] 83 c4 ?? 8a 00 50 8b c7 33 d2 52 50 8b c3 [0-04] 03 ?? ?? 13 54 ?? ?? 71 ?? e8 [0-04] 83 c4 ?? 5a 88 10 [0-04] f3 0f 10 e4 [0-04] 43 4e 75 } //1
		$a_03_1 = {f3 0f 10 ed 33 db a1 [0-06] 03 c3 73 ?? e8 [0-06] 8a 00 [0-06] f3 0f 10 c9 f3 0f 10 e4 34 ?? 8b 15 [0-06] 03 d3 73 ?? e8 [0-06] 88 02 f3 0f 10 db f3 0f 10 ed f3 0f 10 ff 43 81 fb ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}