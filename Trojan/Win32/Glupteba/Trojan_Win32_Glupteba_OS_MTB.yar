
rule Trojan_Win32_Glupteba_OS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c7 08 83 ed 01 90 18 81 3d [0-08] 90 18 81 3d [0-08] 90 18 81 3d [0-08] 90 18 57 e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}