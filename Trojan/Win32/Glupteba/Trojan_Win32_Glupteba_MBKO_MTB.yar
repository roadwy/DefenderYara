
rule Trojan_Win32_Glupteba_MBKO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MBKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 45 f4 01 8b 45 fc 8b 55 f4 8d 1c 10 ba 0c a0 40 00 8b 45 f4 8a 44 02 ff 88 43 ff 3b 4d f4 77 df 6a 40 68 00 30 00 00 68 01 00 06 00 6a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}