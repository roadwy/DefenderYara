
rule Trojan_Win32_Azorult_NV_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 4c 01 15 8b 15 [0-04] 88 [0-02] 8b [0-05] 81 [0-05] 75 0a c7 05 [0-08] 40 3b c1 72 ?? e8 [0-04] e8 [0-04] 33 ?? 3d [0-04] 90 18 40 3d [0-04] 7c ?? c7 05 [0-08] ff 15 } //1
		$a_02_1 = {8a 4c 01 15 8b [0-05] 88 [0-02] 8b [0-05] 81 [0-05] 90 18 40 3b ?? 72 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 [0-09] c7 05 [0-08] ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}