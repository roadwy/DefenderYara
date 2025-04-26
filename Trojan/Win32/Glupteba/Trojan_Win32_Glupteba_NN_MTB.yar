
rule Trojan_Win32_Glupteba_NN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 cf 33 f1 81 3d [0-08] 89 [0-03] 90 18 [0-08] 33 f0 89 b5 [0-04] 8b 85 [0-04] 29 45 [0-0a] ff 8d [0-04] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}