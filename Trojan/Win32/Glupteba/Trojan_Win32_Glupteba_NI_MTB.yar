
rule Trojan_Win32_Glupteba_NI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 85 [0-04] 03 [0-03] 33 [0-03] 33 [0-03] 2b [0-03] 81 3d [0-04] 17 04 00 00 90 18 81 [0-09] ff [0-05] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}