
rule Trojan_Win32_Glupteba_RW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 39 54 24 90 01 01 7e 90 01 01 8b 44 24 90 01 01 8d 0c 02 e8 90 01 04 30 01 42 3b 54 24 90 01 01 7c 90 01 01 81 7c 24 90 01 01 71 11 00 00 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}