
rule Trojan_Win32_Glupteba_NY_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 33 81 ff [0-04] 75 ?? 6a 00 [0-0d] ff 15 [0-0d] 46 3b f7 90 18 e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}