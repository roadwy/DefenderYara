
rule Trojan_Win32_Glupteba_MJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 06 46 85 c0 74 90 01 01 bb 90 02 1f d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 90 02 12 aa 49 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}