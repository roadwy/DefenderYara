
rule Trojan_Win32_LummaC_BS_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 c1 0f b6 c1 f7 d1 89 ca 81 e2 00 ff ff ff 09 d0 31 c1 21 c1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}