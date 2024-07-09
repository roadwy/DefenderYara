
rule Trojan_Win32_Glupteba_AZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 83 c4 ?? 21 db 89 f6 e8 ?? ?? ?? ?? 01 f3 46 31 02 42 81 c3 ?? ?? ?? ?? 01 f3 39 ca 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}