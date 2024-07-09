
rule Trojan_Win32_Glupteba_NX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 33 81 ff [0-04] 75 ?? 6a 00 [0-0d] ff 15 [0-04] 46 3b f7 90 18 e8 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}