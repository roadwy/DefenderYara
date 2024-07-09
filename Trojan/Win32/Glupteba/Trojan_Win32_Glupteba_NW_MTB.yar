
rule Trojan_Win32_Glupteba_NW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 db 74 01 ea 31 0f 81 c7 04 00 00 00 39 df } //1
		$a_01_1 = {31 0f 81 c7 04 00 00 00 39 df 75 ef } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Glupteba_NW_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 df 03 ca 33 [0-03] 33 [0-03] 89 [0-03] 89 [0-05] 8b [0-05] 29 [0-03] 8b [0-05] 29 [0-03] ff [0-05] 8b [0-03] 0f [0-05] 5f 89 [0-03] 89 [0-05] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}