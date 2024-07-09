
rule Trojan_Win32_Azorult_MT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 03 [0-05] 03 [0-05] 8d [0-02] 33 ?? 33 ?? 89 [0-02] 89 [0-05] 89 [0-05] 8b [0-05] 29 [0-02] 81 3d [0-08] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}