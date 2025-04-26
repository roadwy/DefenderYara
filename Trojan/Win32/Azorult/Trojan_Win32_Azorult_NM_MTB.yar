
rule Trojan_Win32_Azorult_NM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 0c 32 3d [0-04] 90 18 46 3b f0 72 c0 } //1
		$a_02_1 = {6a 00 6a 00 6a 00 6a 00 ff 15 [0-04] 6a 00 ff 15 [0-04] a1 [0-04] 3d [0-04] 90 18 e8 [0-04] 81 3d [0-08] 90 18 8b 3d [0-04] 8b 1d [0-04] 33 f6 90 18 81 3d [0-08] 90 18 81 fe [0-04] 90 18 81 3d [0-08] 90 18 46 81 fe [0-04] 7c b9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}