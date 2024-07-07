
rule Trojan_Win32_Glupteba_DAX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 db 74 01 ea 31 0f 81 c7 04 00 00 00 89 db 39 c7 75 } //1
		$a_01_1 = {29 cb 01 db 57 01 cb 5a 09 d9 81 c6 01 00 00 00 83 ec 04 c7 04 24 f8 bd ae dc 5b 81 fe 3e d8 00 01 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}