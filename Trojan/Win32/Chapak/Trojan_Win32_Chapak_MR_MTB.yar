
rule Trojan_Win32_Chapak_MR_MTB{
	meta:
		description = "Trojan:Win32/Chapak.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f7 c1 e6 ?? 81 3d [0-08] 90 18 [0-02] c1 e8 ?? 89 [0-03] 8b [0-03] 01 [0-05] 8d [0-02] 33 ?? 81 [0-09] c7 [0-09] 90 18 31 [0-03] 81 3d [0-08] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}