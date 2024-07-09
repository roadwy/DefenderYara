
rule Trojan_Win32_Glupteba_AMMH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 33 83 ff 0f 75 ?? 33 c9 8d 54 24 08 52 51 33 c0 51 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}