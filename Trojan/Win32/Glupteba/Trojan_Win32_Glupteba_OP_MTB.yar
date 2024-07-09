
rule Trojan_Win32_Glupteba_OP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f5 03 df 81 3d [0-08] 90 18 [0-03] c1 [0-02] c7 05 [0-08] c7 05 [0-08] 89 [0-03] 8b [0-03] 01 [0-03] 81 3d [0-08] 90 18 8b [0-03] 33 [0-03] 33 [0-03] 8d [0-03] e8 [0-04] 81 3d [0-08] 90 18 8d [0-03] e8 [0-04] 83 [0-04] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}