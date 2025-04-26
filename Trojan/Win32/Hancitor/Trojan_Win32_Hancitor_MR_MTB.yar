
rule Trojan_Win32_Hancitor_MR_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b f2 8b 15 [0-04] 01 35 [0-04] 80 3d [0-05] 8d [0-06] 8b 37 90 18 ff 35 [0-04] 69 c0 [0-04] 51 6a 00 50 e8 [0-04] a3 [0-04] 81 [0-05] 89 [0-05] 89 [0-05] 89 37 8b [0-05] 8b [0-05] 8b c1 2b c3 48 48 83 c5 04 a3 [0-04] 81 [0-05] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}