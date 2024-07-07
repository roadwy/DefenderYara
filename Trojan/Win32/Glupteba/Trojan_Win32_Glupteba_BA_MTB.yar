
rule Trojan_Win32_Glupteba_BA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 32 68 98 50 18 6c 5b 81 c2 90 01 04 29 d8 39 fa 75 e7 01 c3 81 e8 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}