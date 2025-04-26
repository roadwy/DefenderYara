
rule Trojan_Win32_Azorult_BAO_MTB{
	meta:
		description = "Trojan:Win32/Azorult.BAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 1a 83 ea fc 83 c3 d4 c1 cb 08 29 fb 8d 5b ff 29 ff 09 df c1 c7 0a c1 cf 02 53 8f 06 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}