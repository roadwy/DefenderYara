
rule Trojan_Win32_Azorult_MS_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e3 8b c6 c1 e8 05 03 [0-05] 03 [0-05] 8d [0-03] 33 ?? 33 ?? 33 ?? 89 ?? ?? 89 [0-05] 89 [0-05] 8b [0-05] 29 [0-03] 81 3d [0-08] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}