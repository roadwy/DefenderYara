
rule Trojan_Win32_Glupteba_K_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 4f e8 18 00 00 00 89 ff 31 11 83 ec 04 89 1c 24 5f 47 41 39 f1 75 e3 29 db 47 c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}