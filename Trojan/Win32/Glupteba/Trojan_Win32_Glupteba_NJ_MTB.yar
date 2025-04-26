
rule Trojan_Win32_Glupteba_NJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f0 8d 0c 2b 33 [0-03] 33 [0-03] 2b [0-03] 81 3d [0-08] 90 18 81 [0-05] 83 [0-07] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}