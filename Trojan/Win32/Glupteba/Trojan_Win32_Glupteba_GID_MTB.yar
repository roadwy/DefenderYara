
rule Trojan_Win32_Glupteba_GID_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 3e 21 db 29 d9 81 c6 04 00 00 00 39 c6 75 90 01 01 89 ca 21 d3 c3 81 c3 90 01 04 89 d6 7f 90 00 } //10
		$a_03_1 = {31 38 81 c0 04 00 00 00 39 f0 75 90 01 01 01 d3 c3 ba 90 01 04 29 ca e2 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}