
rule Trojan_Win32_Glupteba_GJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 d2 83 ec 04 c7 04 24 ?? ?? ?? ?? 8b 14 24 83 c4 04 e8 ?? ?? ?? ?? 29 fa 31 0e 46 39 c6 75 db c3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}